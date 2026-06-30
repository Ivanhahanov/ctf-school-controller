/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	ctfcorev1 "ctf.school/controller/api/core/v1"
	infrav1 "ctf.school/controller/api/infra/v1"
	"golang.org/x/exp/rand"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	TtydImage        = "explabs/terminal-workspace:latest"
	VncImage         = "accetto/ubuntu-vnc-xfce-g3:latest"
	sessionFinalizer = "core.ctf.school/finalizer"
)

// LabSessionReconciler reconciles a LabSession object
type LabSessionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core.ctf.school,resources=labsessions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core.ctf.school,resources=labsessions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.ctf.school,resources=labspaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=infra.ctf.school,resources=labservices;tasks,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces;pods;services;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cilium.io,resources=ciliumnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core.ctf.school,resources=labsessions/finalizers,verbs=update

func (r *LabSessionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := logf.FromContext(ctx)

	// 1. Fetch the LabSession
	session := &ctfcorev1.LabSession{}
	if err := r.Get(ctx, req.NamespacedName, session); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Handle Deletion (Finalizer Logic)
	if !session.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(session, sessionFinalizer) {
			l.Info("Performing cleanup for session", "name", session.Name)
			targetNamespace := fmt.Sprintf("lab-session-%s", session.Name)
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: targetNamespace}}
			_ = r.Delete(ctx, ns)

			controllerutil.RemoveFinalizer(session, sessionFinalizer)
			return ctrl.Result{}, r.Update(ctx, session)
		}
		return ctrl.Result{}, nil
	}

	// 3. Add Finalizer if not present
	if !controllerutil.ContainsFinalizer(session, sessionFinalizer) {
		controllerutil.AddFinalizer(session, sessionFinalizer)
		return ctrl.Result{}, r.Update(ctx, session)
	}

	// 4. Fetch the LabSpace (Blueprint)
	space := &infrav1.LabSpace{}
	if err := r.Get(ctx, client.ObjectKey{Name: session.Spec.LabSpaceRef}, space); err != nil {
		l.Error(err, "Failed to fetch LabSpace", "name", session.Spec.LabSpaceRef)
		return ctrl.Result{}, err
	}

	// Check TTL Expiration
	if session.Status.ExpiredTime != nil && time.Now().After(session.Status.ExpiredTime.Time) {
		l.Info("Lab session expired, triggering deletion", "name", session.Name)
		return ctrl.Result{}, r.Delete(ctx, session)
	}

	// 5. Infrastructure Setup
	targetNamespace := fmt.Sprintf("lab-session-%s", session.Name)
	if err := r.ensureNamespace(ctx, targetNamespace, session); err != nil {
		return ctrl.Result{}, err
	}
	// Isolate the session namespace (Cilium enforces this): no cross-namespace
	// traffic except the gateway/metrics ingress and DNS/internet egress.
	if err := r.ensureNetworkPolicy(ctx, targetNamespace, space, session); err != nil {
		return ctrl.Result{}, err
	}

	// 5b. Fast in-place restart: if a restart was requested after the current
	// pods were created, delete those pods now and let this reconcile recreate
	// them. Far quicker than tearing down and rebuilding the whole session.
	if restarted, err := r.maybeRestart(ctx, session, targetNamespace); err != nil {
		return ctrl.Result{}, err
	} else if restarted {
		session.Status.Phase = "Pending"
		session.Status.Message = "Restarting lab…"
		_ = r.Status().Update(ctx, session)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	// 6. Discovery & Resource Reconciliation
	services := &infrav1.LabServiceList{}
	selector, _ := metav1.LabelSelectorAsSelector(&space.Spec.ServiceSelector)
	if err := r.List(ctx, services, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileWorkspace(ctx, targetNamespace, space, session); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileWorkspaceRoute(ctx, targetNamespace, space, session); err != nil {
		return ctrl.Result{}, err
	}

	for _, svcTemplate := range services.Items {
		if err := r.reconcileServiceResources(ctx, targetNamespace, &svcTemplate, session); err != nil {
			return ctrl.Result{}, err
		}
		// Only expose challenge services through the gateway when the space allows external
		// access. Internal-only spaces keep services reachable only from the workspace pod.
		if !space.Spec.Network.InternalOnly {
			if err := r.reconcileRoute(ctx, targetNamespace, svcTemplate, session); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// 7. Status Sync Logic (Теперь передаем LabSpace)
	return r.syncStatus(ctx, session, targetNamespace, services.Items, space)
}

func (r *LabSessionReconciler) syncStatus(
	ctx context.Context,
	session *ctfcorev1.LabSession,
	ns string,
	svcs []infrav1.LabService,
	space *infrav1.LabSpace,
) (ctrl.Result, error) {
	changed := false
	now := metav1.Now()

	// Инициализация таймеров
	if session.Status.StartTime == nil {
		session.Status.StartTime = &now
		ttlDuration, err := time.ParseDuration(space.Spec.DefaultTTL)
		if err != nil {
			ttlDuration = 1 * time.Hour
		}
		expiredAt := metav1.NewTime(now.Add(ttlDuration))
		session.Status.ExpiredTime = &expiredAt
		session.Status.Phase = "Pending"
		changed = true
	}

	// Сбор реального состояния подов для определения статуса подготовки
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(ns)); err != nil {
		return ctrl.Result{}, err
	}
	newPhase, newMsg := r.computePhase(podList)

	// Update when EITHER the phase or the message changes, so the granular
	// provisioning messages (image pull, starting, waiting-ready…) all surface
	// to the user instead of a single static "Pending".
	if session.Status.Phase != newPhase || session.Status.Message != newMsg {
		session.Status.Phase = newPhase
		session.Status.Message = newMsg
		changed = true
	}

	session.Status.Summary.Namespace = ns

	// Динамическое формирование Workspace эндпоинта для Фронтенда
	domain := os.Getenv("CTF_DOMAIN")
	if domain == "" {
		domain = "ctf.school"
	}
	scheme := envDefault("CTF_SCHEME", "http")
	worksapceHost := scheme + "://" + workspaceHostname(session, domain)

	workspaceType := "Terminal"
	if space.Spec.Workspace.Type == "VNC" {
		workspaceType = "VNC"
	}
	// Формирование списка эндпоинтов
	newEndpoints := []ctfcorev1.Endpoint{
		{
			ServiceName: "workspace",
			Type:        workspaceType,
			Address:     worksapceHost,
		},
	}

	// Services are only published as external endpoints when the space is NOT internal-only.
	// For internal-only spaces the challenge services are reachable solely from inside the
	// workspace (via in-cluster ClusterIP); the workspace is the single entry point.
	if !space.Spec.Network.InternalOnly {
		for _, svc := range svcs {
			if svc.Spec.Exposure != nil {
				addr := fmt.Sprintf("%s://%s-%s.web.%s", scheme, svc.Name, session.Spec.UserId, domain)
				newEndpoints = append(newEndpoints, ctfcorev1.Endpoint{
					ServiceName: svc.Name,
					Type:        svc.Spec.Exposure.Type,
					Address:     addr,
				})
			}
		}
	}

	if len(session.Status.Endpoints) != len(newEndpoints) {
		session.Status.Endpoints = newEndpoints
		changed = true
	}

	if changed {
		if err := r.Status().Update(ctx, session); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Poll quickly while the lab is coming up (snappy, granular feedback), and
	// back off once it is settled and Running.
	requeueAfter := 2 * time.Second
	if session.Status.Phase == "Running" {
		requeueAfter = time.Minute
	}
	if session.Status.ExpiredTime != nil {
		if rem := time.Until(session.Status.ExpiredTime.Time); rem > 0 && rem < requeueAfter {
			requeueAfter = rem
		}
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// computePhase returns a phase (restricted to the CRD's enum:
// Pending/Running/Failed/Terminating/Expired) plus a granular human message.
// The varied feedback lives in the message; the phase stays enum-valid.
func (r *LabSessionReconciler) computePhase(podList *corev1.PodList) (phase, message string) {
	if len(podList.Items) == 0 {
		return "Pending", "Provisioning lab environment…"
	}

	for _, pod := range podList.Items {
		// A terminating pod (e.g. mid-restart) still reports Running with ready
		// containers until it is actually killed. Treat it as not-ready so the
		// phase does NOT settle to Running (which would back the requeue off to a
		// minute and stall recreation) — keep it Pending for a fast turnaround.
		if pod.DeletionTimestamp != nil {
			return "Pending", "Recreating the workspace…"
		}

		// Init container (provisioner) still working.
		for _, s := range pod.Status.InitContainerStatuses {
			if s.Name == "provisioner" && s.State.Running != nil {
				return "Pending", "Downloading task assets…"
			}
		}

		// Inspect waiting containers for a granular message. A large desktop
		// image sits in ContainerCreating while it is pulled, so call that out
		// explicitly — otherwise users think it is stuck.
		for _, cs := range pod.Status.ContainerStatuses {
			w := cs.State.Waiting
			if w == nil {
				continue
			}
			switch {
			case w.Reason == "ImagePullBackOff" || w.Reason == "ErrImagePull":
				return "Pending", "Pulling desktop image…"
			case w.Reason == "CrashLoopBackOff":
				return "Failed", "A container keeps crashing. Try Restart."
			case w.Reason == "ContainerCreating" || w.Reason == "PodInitializing":
				return "Pending", "Pulling image & starting the desktop (first run can take a minute)…"
			default:
				return "Pending", "Starting containers…"
			}
		}

		if pod.Status.Phase == corev1.PodFailed {
			return "Failed", "The lab failed to start. Try Restart."
		}
		if pod.Status.Phase != corev1.PodRunning {
			return "Pending", "Scheduling workspace…"
		}
	}

	// Every pod is Running — wait for readiness probes (desktop + guard).
	for _, pod := range podList.Items {
		for _, cs := range pod.Status.ContainerStatuses {
			if !cs.Ready {
				return "Pending", "Waiting for the desktop to become ready…"
			}
		}
	}

	return "Running", "Lab ready."
}

// maybeRestart deletes the current pods (so the normal reconcile recreates them
// fresh) when a restart has been requested but not yet handled. It marks the
// request handled via an annotation, so the decision is a plain string compare —
// no timestamps, no clock-skew sensitivity, no re-delete loop. Returns true when
// it performed a restart.
func (r *LabSessionReconciler) maybeRestart(ctx context.Context, session *ctfcorev1.LabSession, ns string) (bool, error) {
	requested := session.Annotations[restartRequestedAnnotation]
	if requested == "" || requested == session.Annotations[restartHandledAnnotation] {
		return false, nil
	}

	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(ns)); err != nil {
		return false, err
	}
	grace := labPodGraceSeconds
	for i := range podList.Items {
		p := &podList.Items[i]
		if p.DeletionTimestamp == nil {
			_ = r.Delete(ctx, p, &client.DeleteOptions{GracePeriodSeconds: &grace})
		}
	}

	// Record that we handled this request so we don't loop.
	if session.Annotations == nil {
		session.Annotations = map[string]string{}
	}
	session.Annotations[restartHandledAnnotation] = requested
	if err := r.Update(ctx, session); err != nil {
		return false, err
	}
	return true, nil
}

// nsSelector matches a namespace by its auto-applied metadata.name label.
func nsSelector(name string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": name}}
}

// ensureNetworkPolicy locks a session namespace down to the minimum: a team's
// lab pods can talk to each other and to DNS, can be reached by the gateway
// (workspace) and by vmagent (metrics), and reach the internet only when the
// LabSpace allows it — but cannot reach CTFd, the database, kube internals, or
// any OTHER team's lab namespace. Cilium enforces it.
func (r *LabSessionReconciler) ensureNetworkPolicy(ctx context.Context, ns string, space *infrav1.LabSpace, session *ctfcorev1.LabSession) error {
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	guard := intstr.FromInt(int(guardPort))
	dns := intstr.FromInt(53)

	np := &netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "lab-isolation", Namespace: ns}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, np, func() error {
		if err := ctrl.SetControllerReference(session, np, r.Scheme); err != nil {
			return err
		}
		np.Spec = netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{}, // all pods in the namespace
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{From: []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}}, // intra-namespace
				{ // gateway (workspace) + vmagent (metrics) → guard port
					From: []netv1.NetworkPolicyPeer{
						{NamespaceSelector: nsSelector("envoy-gateway-system")},
						{NamespaceSelector: nsSelector("monitoring")},
					},
					Ports: []netv1.NetworkPolicyPort{{Protocol: &tcp, Port: &guard}},
				},
			},
			Egress: []netv1.NetworkPolicyEgressRule{
				{To: []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}}, // intra-namespace
				{ // DNS
					To:    []netv1.NetworkPolicyPeer{{NamespaceSelector: nsSelector("kube-system")}},
					Ports: []netv1.NetworkPolicyPort{{Protocol: &udp, Port: &dns}, {Protocol: &tcp, Port: &dns}},
				},
			},
		}
		if space.Spec.Network.AllowInternet {
			np.Spec.Egress = append(np.Spec.Egress, netv1.NetworkPolicyEgressRule{
				To: []netv1.NetworkPolicyPeer{{IPBlock: &netv1.IPBlock{
					CIDR:   "0.0.0.0/0",
					Except: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				}}},
			})
		}
		return nil
	})
	return err
}

// ciliumNetworkPolicyGVK identifies the Cilium CNP CRD. We render it as an
// unstructured object so the controller needs no compile-time dependency on the
// Cilium API module — the CRD is provided by the cluster's CNI.
var ciliumNetworkPolicyGVK = schema.GroupVersionKind{
	Group:   "cilium.io",
	Version: "v2",
	Kind:    "CiliumNetworkPolicy",
}

// ensureServiceEgressPolicy renders a per-service CiliumNetworkPolicy that
// allow-lists the exact external destinations declared in LabService.Spec.Egress
// (FQDNs and/or CIDRs), scoped to that service's pods only. This is additive on
// top of the namespace-wide lab-isolation policy, so it grants a single service
// access to e.g. api.deepseek.com without opening LabSpace-wide AllowInternet.
//
// When the service declares no egress rules we delete any stale policy, keeping
// the operation idempotent. FQDN matching relies on Cilium's DNS proxy, so every
// policy also permits DNS to kube-dns with L7 visibility (rules.dns matchPattern).
func (r *LabSessionReconciler) ensureServiceEgressPolicy(ctx context.Context, ns string, labSvc *infrav1.LabService, session *ctfcorev1.LabSession) error {
	name := "egress-" + labSvc.Name
	cnp := &unstructured.Unstructured{}
	cnp.SetGroupVersionKind(ciliumNetworkPolicyGVK)
	cnp.SetName(name)
	cnp.SetNamespace(ns)

	// No rules → ensure no leftover policy exists.
	if len(labSvc.Spec.Egress) == 0 {
		err := r.Delete(ctx, cnp)
		if err != nil && !errors.IsNotFound(err) {
			return err
		}
		return nil
	}

	// Base egress every service keeps: reach sibling pods/workspace in the same
	// namespace, and resolve DNS via kube-dns (with the L7 visibility Cilium's
	// toFQDNs needs). The external destinations follow.
	egress := []interface{}{
		map[string]interface{}{"toEndpoints": []interface{}{map[string]interface{}{}}},
		dnsEgressRule(),
	}
	for _, rule := range labSvc.Spec.Egress {
		if e := fqdnEgressRule(rule); e != nil {
			egress = append(egress, e)
		}
		if e := cidrEgressRule(rule); e != nil {
			egress = append(egress, e)
		}
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, cnp, func() error {
		if err := ctrl.SetControllerReference(session, cnp, r.Scheme); err != nil {
			return err
		}
		spec := map[string]interface{}{
			"endpointSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{"ctf.school/svc": labSvc.Name},
			},
			// Selecting an endpoint for egress puts it in egress default-deny. Adding
			// any egress rule does NOT touch ingress, but a Cilium policy that also
			// declares ingress flips the endpoint into ingress default-deny — so we
			// must restate the intra-namespace allow here, otherwise the workspace
			// (and sibling services) lose access to this service. This keeps the
			// per-service policy self-contained instead of silently depending on the
			// namespace-wide lab-isolation NetworkPolicy.
			"ingress": []interface{}{
				map[string]interface{}{
					// Empty endpoint selector = every endpoint in THIS namespace
					// (Cilium scopes it to the policy's namespace automatically).
					"fromEndpoints": []interface{}{map[string]interface{}{}},
				},
			},
			"egress": egress,
		}
		return unstructured.SetNestedField(cnp.Object, spec, "spec")
	})
	return err
}

// dnsEgressRule lets the service resolve names via kube-dns and gives Cilium's
// DNS proxy the visibility it needs to populate the toFQDNs IP cache.
func dnsEgressRule() map[string]interface{} {
	return map[string]interface{}{
		"toEndpoints": []interface{}{
			map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"k8s:io.kubernetes.pod.namespace": "kube-system",
					"k8s:k8s-app":                     "kube-dns",
				},
			},
		},
		"toPorts": []interface{}{
			map[string]interface{}{
				"ports": []interface{}{
					map[string]interface{}{"port": "53", "protocol": "ANY"},
				},
				"rules": map[string]interface{}{
					"dns": []interface{}{
						map[string]interface{}{"matchPattern": "*"},
					},
				},
			},
		},
	}
}

// fqdnEgressRule renders the toFQDNs section of an EgressRule, or nil if it
// declares no FQDNs. A leading "*." selects matchPattern (wildcard), otherwise
// matchName (exact host).
func fqdnEgressRule(rule infrav1.EgressRule) map[string]interface{} {
	if len(rule.FQDNs) == 0 {
		return nil
	}
	fqdns := make([]interface{}, 0, len(rule.FQDNs))
	for _, name := range rule.FQDNs {
		if strings.Contains(name, "*") {
			fqdns = append(fqdns, map[string]interface{}{"matchPattern": name})
		} else {
			fqdns = append(fqdns, map[string]interface{}{"matchName": name})
		}
	}
	out := map[string]interface{}{"toFQDNs": fqdns}
	if tp := toPorts(rule.Ports); tp != nil {
		out["toPorts"] = tp
	}
	return out
}

// cidrEgressRule renders the toCIDR section of an EgressRule, or nil if it
// declares no CIDRs.
func cidrEgressRule(rule infrav1.EgressRule) map[string]interface{} {
	if len(rule.CIDRs) == 0 {
		return nil
	}
	cidrs := make([]interface{}, 0, len(rule.CIDRs))
	for _, c := range rule.CIDRs {
		cidrs = append(cidrs, c)
	}
	out := map[string]interface{}{"toCIDR": cidrs}
	if tp := toPorts(rule.Ports); tp != nil {
		out["toPorts"] = tp
	}
	return out
}

// toPorts converts an EgressRule's port list into a Cilium toPorts block, or nil
// when no ports are specified (meaning: all ports allowed).
func toPorts(ports []infrav1.EgressPort) []interface{} {
	if len(ports) == 0 {
		return nil
	}
	entries := make([]interface{}, 0, len(ports))
	for _, p := range ports {
		proto := string(p.Protocol)
		if proto == "" {
			proto = "TCP"
		}
		entries = append(entries, map[string]interface{}{
			"port":     fmt.Sprintf("%d", p.Port),
			"protocol": proto,
		})
	}
	return []interface{}{map[string]interface{}{"ports": entries}}
}

func (r *LabSessionReconciler) ensureNamespace(ctx context.Context, name string, owner *ctfcorev1.LabSession) error {
	ns := &corev1.Namespace{}
	err := r.Get(ctx, client.ObjectKey{Name: name}, ns)

	if errors.IsNotFound(err) {
		ns = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"ctf.school/session-owner": owner.Name,
				},
			},
		}
		return r.Create(ctx, ns)
	}
	return err
}
// workspaceHostname is the per-session external host for the workspace. It must
// be unique per LabSession (session.Name already is: lab-<salt>-c<challengeID>),
// otherwise two challenges sharing a LabSpace would produce colliding HTTPRoutes.
func workspaceHostname(session *ctfcorev1.LabSession, domain string) string {
	base := strings.TrimPrefix(session.Name, "lab-")
	return fmt.Sprintf("workspace-%s.%s", cleanDNSName(base), domain)
}

// gatewayParentRef points session routes at the shared CTFd gateway. Name and
// namespace are env-overridable; defaults match k8s/gateway (Gateway "ctfd" in
// namespace "ctfd"). The previous hardcoded "external-gateway"/"gateway-system"
// did not exist, so workspace routes never attached → 404.
func gatewayParentRef() gatewayv1.ParentReference {
	name := os.Getenv("CTF_GATEWAY_NAME")
	if name == "" {
		name = "ctfd"
	}
	nsStr := os.Getenv("CTF_GATEWAY_NAMESPACE")
	if nsStr == "" {
		nsStr = "ctfd"
	}
	ns := gatewayv1.Namespace(nsStr)
	return gatewayv1.ParentReference{
		Name:      gatewayv1.ObjectName(name),
		Namespace: &ns,
	}
}

func (r *LabSessionReconciler) reconcileWorkspaceRoute(ctx context.Context, ns string, space *infrav1.LabSpace, session *ctfcorev1.LabSession) error {
	domain := os.Getenv("CTF_DOMAIN")
	if domain == "" {
		domain = "ctf.school" // Дефолтное значение
	}

	// Unique per session so challenges sharing a LabSpace don't collide.
	hostname := gatewayv1.Hostname(workspaceHostname(session, domain))

	// Маршрутизируем на guard-сайдкар, а не на сырой порт десктопа.
	targetPort := guardPort

	workspaceSvcName := fmt.Sprintf("workspace-%s", session.Name)

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("workspace-route-%s", session.Name),
			Namespace: ns,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, route, func() error {
		// Устанавливаем OwnerReference, чтобы K8s сам удалил route при удалении сессии
		if err := ctrl.SetControllerReference(session, route, r.Scheme); err != nil {
			return err
		}

		route.Spec.CommonRouteSpec.ParentRefs = []gatewayv1.ParentReference{gatewayParentRef()}
		route.Spec.Hostnames = []gatewayv1.Hostname{hostname}
		route.Spec.Rules = []gatewayv1.HTTPRouteRule{{
			BackendRefs: []gatewayv1.HTTPBackendRef{
				{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName(workspaceSvcName),
							Port: (*gatewayv1.PortNumber)(ptrInt32(targetPort)),
						},
					},
				},
			},
		}}
		return nil
	})
	return err
}

func (r *LabSessionReconciler) reconcileWorkspace(
	ctx context.Context, ns string,
	space *infrav1.LabSpace,
	session *ctfcorev1.LabSession,
) error {
	tasks, err := r.getTasksForSpace(ctx, space)
	if err != nil {
		return err
	}

	volumes := []corev1.Volume{
		{Name: "workspace-storage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "tasks-storage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}

	// Добавляем агент (checker) ТОЛЬКО если это не VNC (или если тип Terminal)
	// Без агента провизия тасок через S3 внутри этого пода работать не будет, учтите это
	podName := fmt.Sprintf("workspace-%s", session.Name)

	// Собираем контейнеры динамически. Guard-сайдкар фронтит десктоп: проверяет
	// team-scoped токен и инжектит watermark + защиту от захвата экрана.
	containers := []corev1.Container{
		r.buildWorkspaceInterface(space, tasks, session),
		guardSidecar(space, session),
	}

	// Добавляем агент (checker) ТОЛЬКО если это не VNC (или если тип Terminal)
	// Без агента провизия тасок через S3 внутри этого пода работать не будет, учтите это
	if space.Spec.Workspace.Type == "Termnial" {
		containers = append(containers, r.buildGlobalChecker(tasks, session, space.Spec.Workspace.Tasks))
	}

	workspacePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
			Labels: map[string]string{
				"app":                podName,
				"ctf.school/role":    "workspace",
				"ctf.school/session": session.Name,
			},
		},
		Spec: corev1.PodSpec{
			Volumes:                       volumes,
			Containers:                    containers,
			TerminationGracePeriodSeconds: ptrInt64(labPodGraceSeconds),
		},
	}

	if err := ctrl.SetControllerReference(session, workspacePod, r.Scheme); err != nil {
		return err
	}

	if err := r.createOrUpdatePod(ctx, workspacePod); err != nil {
		return err
	}

	return r.ensureWorkspaceService(ctx, ns, podName, session, space)
}

func (r *LabSessionReconciler) ensureWorkspaceService(ctx context.Context, ns, podName string, session *ctfcorev1.LabSession, space *infrav1.LabSpace) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: ns,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		if err := ctrl.SetControllerReference(session, svc, r.Scheme); err != nil {
			return err
		}
		svc.Spec.Selector = map[string]string{"app": podName}

		// Внешний трафик всегда идёт через guard-сайдкар (порт 8080), который
		// проксирует на десктоп и инжектит защиту. Сырой порт десктопа наружу
		// не публикуется.
		svc.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "web",
				Port:       guardPort,
				TargetPort: intstr.FromInt(int(guardPort)),
			},
		}
		return nil
	})
	return err
}

func (r *LabSessionReconciler) buildWorkspaceInterface(space *infrav1.LabSpace, tasks []infrav1.Task, sess *ctfcorev1.LabSession) corev1.Container {
	image := space.Spec.Workspace.Image
	if image == "" {
		if space.Spec.Workspace.Type == "VNC" {
			image = VncImage // Константа "accetto/ubuntu-vnc-xfce-g3:latest"
		} else if space.Spec.Workspace.Type == "Terminal" {
			image = TtydImage
		} else {
			image = "ctf.school/default-workspace:latest"
		}
	}
	//allEnv := r.mergeTaskEnvs(tasks, sess)
	portName := "ttyd"
	containerPort := int32(7681)

	if space.Spec.Workspace.Type == "VNC" {
		portName = "novnc"
		containerPort = int32(6901)
	}

	container := corev1.Container{
		Name:            "interface",
		Image:           image,
		ImagePullPolicy: corev1.PullIfNotPresent,
		WorkingDir:      "/workspace",
		VolumeMounts: []corev1.VolumeMount{
			{Name: "workspace-storage", MountPath: "/workspace"},
		},
		Env: []corev1.EnvVar{
			{Name: "USERNAME", Value: sess.Spec.UserId},
			{Name: "TASK_SLUG", Value: sess.Spec.LabSpaceRef},
		},
		Ports: []corev1.ContainerPort{
			{
				Name:          portName,
				ContainerPort: containerPort,
			},
		},
	}

	// 3. Для образов accetto часто требуются базовые параметры headless-режима
	if space.Spec.Workspace.Type == "VNC" {
		container.Env = append(container.Env,
			corev1.EnvVar{Name: "VNC_COL_DEPTH", Value: "24"},
			corev1.EnvVar{Name: "VNC_RESOLUTION", Value: "1280x1024"},
			corev1.EnvVar{Name: "VNC_PW", Value: "vncpassword"}, // Пароль по умолчанию, если нужен
		)
	}

	return container
}

func (r *LabSessionReconciler) buildGlobalChecker(
	tasks []infrav1.Task,
	session *ctfcorev1.LabSession,
	s3Key string,
) corev1.Container {
	allEnv := r.mergeTaskEnvs(tasks, session)

	// Добавляем переменные для провизии S3 и аутентификации токена
	allEnv = append(allEnv,
		// Провизия тасок при старте агента
		corev1.EnvVar{Name: "S3_ENDPOINT", Value: "http://seaweedfs-s3.default:8333"},
		corev1.EnvVar{Name: "S3_BUCKET", Value: "ctf"},
		corev1.EnvVar{Name: "S3_KEY", Value: s3Key}, // передавать через аргумент
		corev1.EnvVar{Name: "S3_ACCESS_KEY", Value: "YourSWUser"},
		corev1.EnvVar{Name: "S3_SECRET_KEY", Value: "NjZhOGFmYjdlYTI1NjljZDUyMGRlNjk1"},

		// Секрет для HMAC-токенов — тот же что знает API
		// В продакшене читать из k8s Secret, не хардкодить
		// corev1.EnvVar{
		// 	Name: "AGENT_TOKEN_SECRET",
		// 	ValueFrom: &corev1.EnvVarSource{
		// 		SecretKeyRef: &corev1.SecretKeySelector{
		// 			LocalObjectReference: corev1.LocalObjectReference{Name: "ctf-agent-secret"},
		// 			Key:                  "token-secret",
		// 		},
		// 	},
		// },
		// // HMAC_SECRET и USER_SALT для генерации флагов — как раньше
		// corev1.EnvVar{
		// 	Name: "HMAC_SECRET",
		// 	ValueFrom: &corev1.EnvVarSource{
		// 		SecretKeyRef: &corev1.SecretKeySelector{
		// 			LocalObjectReference: corev1.LocalObjectReference{Name: "ctf-agent-secret"},
		// 			Key:                  "hmac-secret",
		// 		},
		// 	},
		// },
		corev1.EnvVar{
			Name: "AGENT_TOKEN_SECRET", Value: "test",
		},
		// HMAC_SECRET и USER_SALT для генерации флагов — как раньше
		corev1.EnvVar{
			Name: "HMAC_SECRET", Value: "test",
		},
		corev1.EnvVar{Name: "USER_SALT", Value: session.Spec.UserId},
	)

	return corev1.Container{
		Name:  "checker",
		Image: "explabs/lab-agent",
		Env:   allEnv,
		Ports: []corev1.ContainerPort{
			{ContainerPort: 8888, Protocol: corev1.ProtocolTCP}, // internal API
			{ContainerPort: 8889, Protocol: corev1.ProtocolTCP}, // public (CLI)
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: "tasks-storage", MountPath: "/opt/tasks"},
			{Name: "workspace-storage", MountPath: "/workspace"},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/ready",
					Port: intstr.FromInt(8889),
				},
			},
			InitialDelaySeconds: 2,
			PeriodSeconds:       3,
			FailureThreshold:    60, // даём до 3 минут на загрузку тасок
		},
	}
}

func (r *LabSessionReconciler) getTasksForSpace(ctx context.Context, space *infrav1.LabSpace) ([]infrav1.Task, error) {
	taskList := &infrav1.TaskList{}

	// Преобразуем LabelSelector из LabSpaceSpec в понятный для клиента формат
	selector, err := metav1.LabelSelectorAsSelector(&space.Spec.ServiceSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid service selector in labspace: %w", err)
	}

	// Листим таски по всему кластеру (или в неймспейсе оператора)
	if err := r.List(ctx, taskList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, fmt.Errorf("failed to list tasks: %w", err)
	}

	return taskList.Items, nil
}

func (r *LabSessionReconciler) mergeTaskEnvs(tasks []infrav1.Task, session *ctfcorev1.LabSession) []corev1.EnvVar {
	var result []corev1.EnvVar

	// for _, t := range tasks {
	// 	// Генерируем ENV для конкретной таски
	// 	taskEnvs := r.buildEnvVarsFromTask(&t, session)

	// 	// Добавляем префикс к именам переменных, чтобы избежать коллизий,
	// 	// или просто добавляем как есть, если имена уникальны
	// 	result = append(result, taskEnvs...)
	// }

	// Добавляем общие данные сессии
	result = append(result, corev1.EnvVar{Name: "SESSION_ID", Value: session.Name})
	result = append(result, corev1.EnvVar{Name: "USER_ID", Value: session.Spec.UserId})

	return result
}
func (r *LabSessionReconciler) reconcileServiceResources(ctx context.Context, ns string, labSvc *infrav1.LabService, session *ctfcorev1.LabSession) error {
	// 1. Обработка Environment Variables (включая Dynamic)
	envVars := r.buildEnvVars(labSvc, session)

	// 2. Создаем Pod (упрощенно, можно использовать Deployment для надежности)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      labSvc.Name,
			Namespace: ns,
			Labels: map[string]string{
				"app":             labSvc.Name,
				"ctf.school/svc":  labSvc.Name,
				"ctf.school/sess": session.Name,
			},
		},
		Spec: corev1.PodSpec{
			TerminationGracePeriodSeconds: ptrInt64(labPodGraceSeconds),
			Containers: []corev1.Container{
				{
					Name:            "challenge",
					Image:           labSvc.Spec.Image,
					ImagePullPolicy: labSvc.Spec.ImagePullPolicy,
					Command:         labSvc.Spec.Command,
					Args:            labSvc.Spec.Args,
					Ports:           labSvc.Spec.Ports,
					Env:             envVars,
					Resources:       labSvc.Spec.Resources,
					LivenessProbe:   labSvc.Spec.Liveness,
					ReadinessProbe:  labSvc.Spec.Readiness,
				},
			},
		},
	}

	// switch labSvc.Spec.Exposure.Type {
	// case "Terminal":
	// 	// Добавляем ttyd как sidecar
	// 	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
	// 		Name:  "ttyd",
	// 		Image: TtydImage,
	// 		Args:  []string{"ttyd", "-W", "-p", "7681", "bash"},
	// 		Ports: []corev1.ContainerPort{{Name: "ttyd", ContainerPort: 7681}},
	// 	})
	// case "VNC":
	// 	// Для VNC часто проще использовать один подготовленный GUI образ,
	// 	// но если нужно "прицепиться" к challenge, используем sidecar с noVNC
	// 	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
	// 		Name:  "vnc",
	// 		Image: "netdata/novnc:latest", // Пример легкого прокси
	// 		Ports: []corev1.ContainerPort{{Name: "vnc", ContainerPort: 8080}},
	// 	})
	// }

	// Create or Update Pod logic
	// foundPod := &corev1.Pod{}
	// err := r.Get(ctx, client.ObjectKey{Name: pod.Name, Namespace: ns}, foundPod)
	// if err != nil && errors.IsNotFound(err) {
	// 	if err := r.Create(ctx, pod); err != nil {
	// 		return err
	// 	}
	// }
	if err := r.createOrUpdatePod(ctx, pod); err != nil {
		return err
	}

	// 3. Per-service egress allow-list (CiliumNetworkPolicy with toFQDNs/toCIDR).
	if err := r.ensureServiceEgressPolicy(ctx, ns, labSvc, session); err != nil {
		return err
	}

	// 4. Создаем Service для доступа внутри кластера
	return r.ensureService(ctx, ns, labSvc, session)
}

func (r *LabSessionReconciler) ensureService(ctx context.Context, ns string, labSvc *infrav1.LabService, session *ctfcorev1.LabSession) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      labSvc.Name,
			Namespace: ns,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		// Описываем желаемое состояние Service
		if svc.Labels == nil {
			svc.Labels = make(map[string]string)
		}
		svc.Labels["app"] = labSvc.Name

		svc.Spec.Selector = map[string]string{"app": labSvc.Name}

		ports := []corev1.ServicePort{}
		for _, p := range labSvc.Spec.Ports {
			ports = append(ports, corev1.ServicePort{
				Name: p.Name,
				Port: p.ContainerPort,
			})
		}
		svc.Spec.Ports = ports

		return nil
	})
	return err
}

func (r *LabSessionReconciler) reconcileRoute(ctx context.Context, ns string, labSvc infrav1.LabService, session *ctfcorev1.LabSession) error {
	if labSvc.Spec.Exposure == nil || labSvc.Spec.Exposure.Type != "HTTP" {
		return nil
	}

	domain := os.Getenv("CTF_DOMAIN")
	if domain == "" {
		domain = "ctf.school"
	}
	hostname := gatewayv1.Hostname(fmt.Sprintf("%s-%s.web.%s", labSvc.Name, session.Spec.UserId, domain))

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      labSvc.Name,
			Namespace: ns,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, route, func() error {
		route.Spec.CommonRouteSpec.ParentRefs = []gatewayv1.ParentReference{gatewayParentRef()}
		route.Spec.Hostnames = []gatewayv1.Hostname{hostname}

		// Исправленная вложенность BackendRefs
		route.Spec.Rules = []gatewayv1.HTTPRouteRule{{
			BackendRefs: []gatewayv1.HTTPBackendRef{
				{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName(labSvc.Name),
							Port: (*gatewayv1.PortNumber)(ptrInt32(labSvc.Spec.Ports[0].ContainerPort)),
						},
					},
				},
			},
		}}
		return nil
	})
	return err
}

// Helpers for pointers
func ptrString(s string) *string { return &s }
func ptrInt32(i int32) *int32    { return &i }
func ptrInt64(i int64) *int64    { return &i }

// labPodGraceSeconds is the termination grace period for ephemeral lab pods.
// The default of 30s makes Stop/Restart feel sluggish; these pods hold no state
// worth draining, so kill them almost immediately.
const labPodGraceSeconds int64 = 2

// Restart is requested by bumping restartRequestedAnnotation (any new value).
// The controller records the value it acted on in restartHandledAnnotation and
// only restarts when the two differ — a string compare, immune to clock skew.
// A restart recreates just the pods in place, reusing the namespace/services/
// routes instead of tearing the whole session down and rebuilding it.
const (
	restartRequestedAnnotation = "ctf.school/restart-requested-at"
	restartHandledAnnotation   = "ctf.school/restart-handled"
)

func (r *LabSessionReconciler) buildEnvVars(labSvc *infrav1.LabService, session *ctfcorev1.LabSession) []corev1.EnvVar {
	var result []corev1.EnvVar

	for _, e := range labSvc.Spec.Env {
		val := e.Value

		if e.DynamicValue != nil {
			switch e.DynamicValue.Type {
			case "random":
				val = generateRandomString(e.DynamicValue.Length)
			case "hmac":
				// Flag = platform format wrapping the per-team HMAC token. The
				// format is platform-wide (CTF_FLAG_FORMAT) — NOT per-service —
				// so it is set in one place and always matches CTFd's derivation.
				val = fmt.Sprintf(flagFormat(), hash(labSvc.Name+session.Spec.UserId))
			}
		}

		result = append(result, corev1.EnvVar{
			Name:  e.Name,
			Value: val,
		})
	}

	// Добавляем системные переменные
	result = append(result, corev1.EnvVar{Name: "USER_ID", Value: session.Spec.UserId})

	return result
}

// generateRandomString creates a random alphanumeric string of a given length
func generateRandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

// hash generating a deterministic string based on UserId and a secret
// flagTokenLen is the length of the derived flag body (base64url chars). 24 of a
// 64-symbol alphabet ≈ 2^144 entropy — far beyond brute-forcing.
const flagTokenLen = 24

// flagFormat is the platform-wide flag wrapper (a %s format). Set once via env
// (the SAME value CTFd uses), so challenge authors never specify it. e.g.
// CTF_FLAG_FORMAT="AlphaCTF{%s}".
func flagFormat() string {
	return envDefault("CTF_FLAG_FORMAT", "CTF{%s}")
}

// hash derives the flag token. It MUST match CTFd's _derive_flag exactly:
// base64url(HMAC-SHA256(CTF_SCHOOL_SECRET, flagService+salt))[:flagTokenLen].
// base64url is mixed-case alphanumeric (+ -_); the secret comes from env so both
// sides share one source of truth.
func hash(input string) string {
	secret := envDefault("CTF_SCHOOL_SECRET", "ctf-school-secret-key")
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:flagTokenLen]
}

func (r *LabSessionReconciler) createOrUpdatePod(ctx context.Context, pod *corev1.Pod) error {
	found := &corev1.Pod{}
	err := r.Get(ctx, client.ObjectKey{Name: pod.Name, Namespace: pod.Namespace}, found)

	if err != nil {
		if errors.IsNotFound(err) {
			// Создаем, если не найден
			return r.Create(ctx, pod)
		}
		return err
	}

	// Если под найден, в Kubernetes мы обычно его не обновляем (т.к. Spec пода почти весь неизменяемый)
	// Но можно проверить labels или image и при необходимости перезапустить.
	return nil
}

func cleanDNSName(s string) string {
	// Переводим в нижний регистр и убираем запрещенные в DNS символы
	res := strings.ToLower(s)
	res = strings.ReplaceAll(res, "_", "-")
	res = strings.ReplaceAll(res, "@", "-")
	return res
}

// SetupWithManager sets up the controller with the Manager.
func (r *LabSessionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ctfcorev1.LabSession{}).
		Named("core-labsession").
		Complete(r)
}
