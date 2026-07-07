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
	"k8s.io/apimachinery/pkg/api/resource"
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

// Conservative default disk budget for lab pods. Every value is a cap the
// platform applies when the CRD leaves it unset, so no emptyDir or writable
// rootfs is unbounded — a runaway process (large files, a "fork bomb" that
// spools to disk) hits its own cap instead of filling node ephemeral storage
// and triggering a node-wide DiskPressure eviction. Override per-CRD via
// Workspace.Resources / Workspace.StorageLimit and LabService.Resources /
// LabService.StorageLimit. NOTE: PID-exhaustion (a classic fork bomb) is a
// separate lever — it needs a kubelet podPidsLimit at the node level, which is
// not expressible in the PodSpec/CRD (tracked as a follow-up).
var (
	// Workspace desktop container: full GUI/terminal, writable rootfs. The
	// cpu/memory REQUESTS match the LimitRange defaults these pods used before they
	// became explicit (100m / 256Mi) — existing LabSpace quotas are sized around
	// that floor, so keep it here or a tight requests.memory quota rejects the pod
	// (desktop request + guard 32Mi must fit). Raise headroom via the LimitS, not
	// the requests, or bump the LabSpace quota.
	defaultWorkspaceCPURequest       = resource.MustParse("100m")
	defaultWorkspaceCPULimit         = resource.MustParse("1")
	defaultWorkspaceMemRequest       = resource.MustParse("256Mi")
	defaultWorkspaceMemLimit         = resource.MustParse("2Gi")
	defaultWorkspaceEphemeralRequest = resource.MustParse("256Mi")
	defaultWorkspaceEphemeralLimit   = resource.MustParse("1Gi")

	// emptyDir SizeLimits (writes past these fail with ENOSPC on the volume).
	defaultWorkspaceStorageLimit = resource.MustParse("1Gi")   // /workspace
	defaultTasksStorageLimit     = resource.MustParse("512Mi") // /opt/tasks
	defaultServiceTmpLimit       = resource.MustParse("256Mi") // challenge /tmp

	// Challenge container: default ephemeral-storage limit (writable rootfs layer).
	defaultServiceEphemeralLimit = resource.MustParse("512Mi")

	// Session-namespace LimitRange per-container ephemeral-storage defaults. These
	// admit pods that omit ephemeral-storage (e.g. the checker agent) when a quota
	// enforces limits/requests.ephemeral-storage.
	defaultLimitRangeEphemeralRequest = resource.MustParse("256Mi")
	defaultLimitRangeEphemeralLimit   = resource.MustParse("1Gi")

	// Guard sidecar: tiny distroless reverse proxy, read-only rootfs.
	guardEphemeralRequest = resource.MustParse("16Mi")
	guardEphemeralLimit   = resource.MustParse("64Mi")
)

// setDefaultQty fills list[name] with def only when the caller left it unset,
// so author-supplied values always win over the platform default.
func setDefaultQty(list corev1.ResourceList, name corev1.ResourceName, def resource.Quantity) {
	if _, ok := list[name]; !ok {
		list[name] = def.DeepCopy()
	}
}

// workspaceResources builds the desktop container's requirements from the
// author's Workspace.Resources, backfilling every unset field with its
// conservative default. The ephemeral-storage limit is therefore always present
// so the writable-rootfs desktop can never fill node disk.
func workspaceResources(space *infrav1.LabSpace) corev1.ResourceRequirements {
	res := corev1.ResourceRequirements{Requests: corev1.ResourceList{}, Limits: corev1.ResourceList{}}
	if r := space.Spec.Workspace.Resources; r != nil {
		for k, v := range r.Requests {
			res.Requests[k] = v
		}
		for k, v := range r.Limits {
			res.Limits[k] = v
		}
	}
	setDefaultQty(res.Requests, corev1.ResourceCPU, defaultWorkspaceCPURequest)
	setDefaultQty(res.Requests, corev1.ResourceMemory, defaultWorkspaceMemRequest)
	setDefaultQty(res.Requests, corev1.ResourceEphemeralStorage, defaultWorkspaceEphemeralRequest)
	setDefaultQty(res.Limits, corev1.ResourceCPU, defaultWorkspaceCPULimit)
	setDefaultQty(res.Limits, corev1.ResourceMemory, defaultWorkspaceMemLimit)
	setDefaultQty(res.Limits, corev1.ResourceEphemeralStorage, defaultWorkspaceEphemeralLimit)
	return res
}

// serviceResources returns the challenge container's requirements: the author's
// LabService.Resources with a default ephemeral-storage LIMIT injected when
// absent, so a challenge can't fill node disk via its writable rootfs. CPU/memory
// are left to the author and the namespace LimitRange.
func serviceResources(labSvc *infrav1.LabService) corev1.ResourceRequirements {
	res := *labSvc.Spec.Resources.DeepCopy()
	if res.Limits == nil {
		res.Limits = corev1.ResourceList{}
	}
	setDefaultQty(res.Limits, corev1.ResourceEphemeralStorage, defaultServiceEphemeralLimit)
	return res
}

// LabSessionReconciler reconciles a LabSession object
type LabSessionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=core.ctf.school,resources=labsessions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core.ctf.school,resources=labsessions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core.ctf.school,resources=labspaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=infra.ctf.school,resources=labservices;tasks,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces;pods;services;configmaps;resourcequotas;limitranges;secrets,verbs=get;list;watch;create;update;patch;delete
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
	// Stamp the private task-registry pull secret into the session namespace (no-op when
	// CTF_REGISTRY_PULLSECRET is unset — dev/kind pulls kind-loaded/public images).
	if err := r.ensurePullSecret(ctx, targetNamespace, session); err != nil {
		return ctrl.Result{}, err
	}
	// Cap the whole namespace's aggregate resource usage from LabSpace.Spec.Resources,
	// and seed per-container defaults so pods that omit resources are still admitted
	// under the quota (workspace/guard/agent don't set their own requests/limits).
	if err := r.ensureResourceQuota(ctx, targetNamespace, space, session); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.ensureLimitRange(ctx, targetNamespace, space, session); err != nil {
		return ctrl.Result{}, err
	}
	// Isolate the session namespace (Cilium enforces this): no cross-namespace
	// traffic except the gateway/metrics ingress and DNS/internet egress.
	if err := r.ensureBaselinePolicy(ctx, targetNamespace, space, session); err != nil {
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

// ensureBaselinePolicy locks a session namespace down to the minimum, expressed
// as a single per-namespace CiliumNetworkPolicy (one engine, one source of truth).
// Lab pods may talk to each other and to DNS, be reached by the gateway (workspace)
// and by vmagent (metrics), and reach the public internet only when the LabSpace
// sets AllowInternet — but cannot reach CTFd, the database, kube internals, or any
// OTHER team's namespace. Because the policy selects every pod in both directions,
// the namespace is default-deny: anything not listed here (or in a per-service
// egress policy) is dropped. Per-service FQDN egress is layered on top.
func (r *LabSessionReconciler) ensureBaselinePolicy(ctx context.Context, ns string, space *infrav1.LabSpace, session *ctfcorev1.LabSession) error {
	// Migration: drop the legacy native NetworkPolicy now superseded by the CNP.
	stale := &netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "lab-isolation", Namespace: ns}}
	if err := r.Delete(ctx, stale); err != nil && !errors.IsNotFound(err) {
		return err
	}

	egress := []interface{}{
		// intra-namespace: workspace <-> challenge services, services <-> services.
		map[string]interface{}{"toEndpoints": []interface{}{map[string]interface{}{}}},
		// DNS via kube-dns, with the L7 visibility Cilium's toFQDNs depends on
		// (kept here once so per-service policies don't need to restate it).
		dnsEgressRule(),
		// Anti-cheat evidence: the guard ships report-only telemetry to VictoriaLogs
		// in the monitoring namespace (:9428). Narrow allow so it works even when the
		// challenge itself has no internet egress.
		map[string]interface{}{
			"toEndpoints": []interface{}{
				map[string]interface{}{"matchLabels": map[string]interface{}{"k8s:io.kubernetes.pod.namespace": "monitoring"}},
			},
			"toPorts": []interface{}{map[string]interface{}{
				"ports": []interface{}{map[string]interface{}{"port": "9428", "protocol": "TCP"}},
			}},
		},
	}
	if space.Spec.Network.AllowInternet {
		// Explicit "full egress" mode: everything outside the cluster. When set,
		// per-service Egress allow-lists are redundant (world already covers them).
		egress = append(egress, map[string]interface{}{
			"toEntities": []interface{}{"world"},
		})
	}

	cnp := &unstructured.Unstructured{}
	cnp.SetGroupVersionKind(ciliumNetworkPolicyGVK)
	cnp.SetName("lab-baseline")
	cnp.SetNamespace(ns)
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, cnp, func() error {
		if err := ctrl.SetControllerReference(session, cnp, r.Scheme); err != nil {
			return err
		}
		spec := map[string]interface{}{
			"endpointSelector": map[string]interface{}{}, // all pods in THIS namespace
			"ingress": []interface{}{
				// intra-namespace (workspace reaches every service in its ns).
				map[string]interface{}{"fromEndpoints": []interface{}{map[string]interface{}{}}},
				// gateway (workspace UI) + vmagent (metrics) -> guard port.
				map[string]interface{}{
					"fromEndpoints": []interface{}{
						map[string]interface{}{"matchLabels": map[string]interface{}{"k8s:io.kubernetes.pod.namespace": "envoy-gateway-system"}},
						map[string]interface{}{"matchLabels": map[string]interface{}{"k8s:io.kubernetes.pod.namespace": "monitoring"}},
					},
					"toPorts": []interface{}{map[string]interface{}{
						"ports": []interface{}{map[string]interface{}{"port": fmt.Sprintf("%d", guardPort), "protocol": "TCP"}},
					}},
				},
			},
			"egress": egress,
		}
		return unstructured.SetNestedField(cnp.Object, spec, "spec")
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
// (FQDNs and/or CIDRs), scoped to that service's pods only. It is purely additive:
// the intra-namespace reachability, DNS (with the L7 visibility toFQDNs needs) and
// the ingress path all come from the lab-baseline policy, so this object stays a
// minimal, egress-only "exception" — easy to read in a security review.
//
// When the service declares no egress rules we delete any stale policy, keeping
// the operation idempotent (e.g. after Egress is removed from the LabService).
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

	egress := []interface{}{}
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

// pullSecretName is the name of the dockerconfigjson Secret stamped into every session
// namespace so kubelet can pull challenge images from the private task-registry.
const pullSecretName = "task-registry-pull"

// registryPullConfig returns the ~/.docker/config.json contents for the task-registry,
// supplied to the controller via CTF_REGISTRY_PULLSECRET (a secretKeyRef in prod). Empty
// = feature off: dev/kind kind-loads images, and public images need no auth.
func registryPullConfig() string { return os.Getenv("CTF_REGISTRY_PULLSECRET") }

// pullSecretRefs is what goes on a PodSpec.ImagePullSecrets — the stamped secret when the
// feature is on, else nil (harmless to omit for kind-loaded/public images).
func pullSecretRefs() []corev1.LocalObjectReference {
	if registryPullConfig() == "" {
		return nil
	}
	return []corev1.LocalObjectReference{{Name: pullSecretName}}
}

// ensurePullSecret create-or-updates the task-registry pull secret in a session
// namespace. Owned by the (cluster-scoped) session, and the namespace is deleted on
// session end, so it never leaks. No-op when the feature is off.
func (r *LabSessionReconciler) ensurePullSecret(ctx context.Context, ns string, owner *ctfcorev1.LabSession) error {
	cfg := registryPullConfig()
	if cfg == "" {
		return nil
	}
	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: pullSecretName, Namespace: ns},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(cfg)},
	}
	if err := ctrl.SetControllerReference(owner, desired, r.Scheme); err != nil {
		return err
	}
	found := &corev1.Secret{}
	switch err := r.Get(ctx, client.ObjectKey{Name: pullSecretName, Namespace: ns}, found); {
	case errors.IsNotFound(err):
		return r.Create(ctx, desired)
	case err != nil:
		return err
	default:
		found.Type = desired.Type
		found.Data = desired.Data
		return r.Update(ctx, found)
	}
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
					// Pod Security Admission: ENFORCE 'baseline' (blocks privileged,
					// host namespaces, hostPath, extra caps — the desktop's root init
					// still passes), and WARN/AUDIT against 'restricted' for visibility
					// into what isn't yet fully locked down (the desktop container).
					"pod-security.kubernetes.io/enforce":         "baseline",
					"pod-security.kubernetes.io/enforce-version": "latest",
					"pod-security.kubernetes.io/warn":            "restricted",
					"pod-security.kubernetes.io/warn-version":    "latest",
					"pod-security.kubernetes.io/audit":           "restricted",
					"pod-security.kubernetes.io/audit-version":   "latest",
				},
			},
		}
		return r.Create(ctx, ns)
	}
	return err
}

// ensureResourceQuota caps the aggregate resource consumption of a session
// namespace from LabSpace.Spec.Resources. The two ResourceLists are mapped onto
// the quota's prefixed counters: Requests -> requests.<res>, Limits -> limits.<res>
// (so cpu/memory become requests.cpu, limits.memory, … — the names a ResourceQuota
// expects). If neither is set the namespace stays unbounded (no quota object). The
// quota is reconciled in place, so editing the LabSpace re-tightens live sessions.
//
// NOTE: once limits.* / requests.* are enforced, every pod in the namespace must
// declare the matching limits/requests or its creation is rejected. The workspace,
// guard and agent containers don't set their own — ensureLimitRange supplies the
// per-container defaults that satisfy this.
func (r *LabSessionReconciler) ensureResourceQuota(ctx context.Context, ns string, space *infrav1.LabSpace, owner *ctfcorev1.LabSession) error {
	hard := corev1.ResourceList{}
	for name, qty := range space.Spec.Resources.Requests {
		hard[corev1.ResourceName("requests."+string(name))] = qty
	}
	for name, qty := range space.Spec.Resources.Limits {
		hard[corev1.ResourceName("limits."+string(name))] = qty
	}
	if len(hard) == 0 {
		return nil
	}

	quota := &corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "lab-quota", Namespace: ns}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, quota, func() error {
		if quota.Labels == nil {
			quota.Labels = map[string]string{}
		}
		quota.Labels["ctf.school/session-owner"] = owner.Name
		quota.Spec.Hard = hard
		return nil
	})
	return err
}

// ensureLimitRange seeds per-container default requests/limits in the session
// namespace. It is the companion to ensureResourceQuota: a ResourceQuota that caps
// limits.cpu/limits.memory makes the API server REJECT any container that lacks
// those values, and the workspace/guard/agent containers don't set them. The
// LimitRange auto-injects these defaults so such pods are admitted and counted.
// Only created when the quota is (Resources has requests or limits); otherwise the
// namespace is unbounded and no defaults are needed.
//
// The defaults are deliberately modest. They are a floor to keep pods schedulable,
// NOT the sizing — that's LabSpace.Spec.Resources (the aggregate cap). If a
// LabSpace's cap is too small for a full desktop + guard + challenge pods, raise it
// there; the LimitRange only decides what an individual container gets by default.
func (r *LabSessionReconciler) ensureLimitRange(ctx context.Context, ns string, space *infrav1.LabSpace, owner *ctfcorev1.LabSession) error {
	if len(space.Spec.Resources.Requests) == 0 && len(space.Spec.Resources.Limits) == 0 {
		return nil
	}

	lr := &corev1.LimitRange{ObjectMeta: metav1.ObjectMeta{Name: "lab-defaults", Namespace: ns}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, lr, func() error {
		if lr.Labels == nil {
			lr.Labels = map[string]string{}
		}
		lr.Labels["ctf.school/session-owner"] = owner.Name
		lr.Spec.Limits = []corev1.LimitRangeItem{{
			Type: corev1.LimitTypeContainer,
			Default: corev1.ResourceList{ // limits when a container omits them (sized for the desktop)
				corev1.ResourceCPU:              resource.MustParse("1"),
				corev1.ResourceMemory:           resource.MustParse("2Gi"),
				corev1.ResourceEphemeralStorage: defaultLimitRangeEphemeralLimit.DeepCopy(),
			},
			DefaultRequest: corev1.ResourceList{ // requests when a container omits them
				corev1.ResourceCPU:              resource.MustParse("100m"),
				corev1.ResourceMemory:           resource.MustParse("256Mi"),
				corev1.ResourceEphemeralStorage: defaultLimitRangeEphemeralRequest.DeepCopy(),
			},
		}}
		return nil
	})
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

	// Cap both scratch volumes so a runaway process can't fill node ephemeral
	// storage. /workspace is player-controlled (StorageLimit), /opt/tasks holds the
	// provisioned task archive (fixed default).
	wsLimit := defaultWorkspaceStorageLimit
	if l := space.Spec.Workspace.StorageLimit; l != nil {
		wsLimit = *l
	}
	tasksLimit := defaultTasksStorageLimit
	volumes := []corev1.Volume{
		{Name: "workspace-storage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &wsLimit}}},
		{Name: "tasks-storage", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &tasksLimit}}},
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
			ImagePullSecrets:              pullSecretRefs(),
			TerminationGracePeriodSeconds: ptrInt64(labPodGraceSeconds),
		},
	}
	hardenPod(&workspacePod.Spec)

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
		// Author-set Workspace.Resources with conservative defaults backfilled; the
		// ephemeral-storage limit is always present (writable-rootfs desktop).
		Resources: workspaceResources(space),
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
			corev1.EnvVar{Name: "VNC_PW", Value: vncPassword(sess)}, // per-session, secret-derived (not hardcoded)
		)
	}

	// The desktop container's hardening: an author-supplied profile, else the desktop
	// default (root/writable/default-caps — the current images need it). Everything not
	// covered here is still enforced at the pod level by hardenPod.
	profile := space.Spec.Workspace.Security
	if profile == nil {
		profile = desktopDefaultProfile
	}
	container.SecurityContext = containerSecurityContext(profile)

	return container
}

func (r *LabSessionReconciler) buildGlobalChecker(
	tasks []infrav1.Task,
	session *ctfcorev1.LabSession,
	s3Key string,
) corev1.Container {
	allEnv := r.mergeTaskEnvs(tasks, session)

	// S3 provisioning + token/flag secrets for the checker agent. NOTHING is hardcoded:
	// endpoint/bucket are config (env-overridable), S3 credentials come from the
	// controller's own env (a mounted Secret), and the two HMAC keys reuse the split
	// secrets so the agent's flag derivation matches CTFd (HMAC_SECRET = flagSecret) and
	// its token signing matches the guard (AGENT_TOKEN_SECRET = jwtSecret).
	allEnv = append(allEnv,
		corev1.EnvVar{Name: "S3_ENDPOINT", Value: envDefault("CTF_S3_ENDPOINT", "http://seaweedfs-s3.default:8333")},
		corev1.EnvVar{Name: "S3_BUCKET", Value: envDefault("CTF_S3_BUCKET", "ctf")},
		corev1.EnvVar{Name: "S3_KEY", Value: s3Key},
		corev1.EnvVar{Name: "S3_ACCESS_KEY", Value: os.Getenv("CTF_S3_ACCESS_KEY")},
		corev1.EnvVar{Name: "S3_SECRET_KEY", Value: os.Getenv("CTF_S3_SECRET_KEY")},
		corev1.EnvVar{Name: "AGENT_TOKEN_SECRET", Value: jwtSecret()},
		corev1.EnvVar{Name: "HMAC_SECRET", Value: flagSecret()},
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
	challenge := corev1.Container{
		Name:            "challenge",
		Image:           labSvc.Spec.Image,
		ImagePullPolicy: labSvc.Spec.ImagePullPolicy,
		Command:         labSvc.Spec.Command,
		Args:            labSvc.Spec.Args,
		Ports:           labSvc.Spec.Ports,
		Env:             envVars,
		Resources:       serviceResources(labSvc),
		LivenessProbe:   labSvc.Spec.Liveness,
		ReadinessProbe:  labSvc.Spec.Readiness,
		SecurityContext: containerSecurityContext(labSvc.Spec.Security),
	}

	var volumes []corev1.Volume
	// A read-only root filesystem is the default; give the container a writable
	// scratch /tmp (emptyDir) so well-behaved images still work without opting out.
	if labSvc.Spec.Security == nil || !labSvc.Spec.Security.WritableRootFilesystem {
		tmpLimit := defaultServiceTmpLimit
		if l := labSvc.Spec.StorageLimit; l != nil {
			tmpLimit = *l
		}
		volumes = append(volumes, corev1.Volume{
			Name:         "tmp",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &tmpLimit}},
		})
		challenge.VolumeMounts = append(challenge.VolumeMounts, corev1.VolumeMount{Name: "tmp", MountPath: "/tmp"})
	}

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
			Volumes:                       volumes,
			Containers:                    []corev1.Container{challenge},
			ImagePullSecrets:              pullSecretRefs(),
		},
	}
	hardenPod(&pod.Spec)

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
func ptrBool(b bool) *bool       { return &b }

// desktopDefaultProfile is the security profile for the workspace DESKTOP container.
// The workspace is an OFFENSIVE environment — players run nmap (SYN scans need
// CAP_NET_RAW), tcpdump, setuid tools (ping/sudo), bind ports, and write tool output —
// so it runs as root with the container runtime's default capability set (which
// includes NET_RAW) and a writable root filesystem. This is BY DESIGN, not a gap: the
// security boundary for a workspace is CONTAINMENT, not the in-container uid. What must
// hold — and is enforced by hardenPod + the namespace PSA 'baseline' + the Cilium
// network policy — is that the player cannot ESCAPE the box: NO privileged, NO host
// namespaces, NO hostPath, NO CAP_SYS_ADMIN, no service-account token, RuntimeDefault
// seccomp (blocks mount/bpf/keyctl escape syscalls), and network isolation to their own
// namespace + allowed egress. A challenge that needs extra tooling caps (e.g. NET_ADMIN,
// SYS_PTRACE) sets LabSpace.spec.workspace.security.addCapabilities — note that goes
// beyond PSA 'baseline', so such a namespace must relax enforcement.
var desktopDefaultProfile = &infrav1.SecurityProfile{
	AllowRunAsRoot:           true,
	WritableRootFilesystem:   true,
	KeepDefaultCapabilities:  true, // keeps NET_RAW etc. for scanning/packet tools
	AllowPrivilegeEscalation: true, // setuid tools (ping/sudo) + the entrypoint's `su`
}

// containerSecurityContext renders a container SecurityContext from a SecurityProfile.
// A nil profile is the strictest possible: non-root (uid 1000), no privilege
// escalation, ALL capabilities dropped, read-only root fs, RuntimeDefault seccomp.
// Each profile field opts out of exactly one control (secure-by-default).
func containerSecurityContext(p *infrav1.SecurityProfile) *corev1.SecurityContext {
	if p == nil {
		p = &infrav1.SecurityProfile{}
	}
	sc := &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptrBool(p.AllowPrivilegeEscalation),
		ReadOnlyRootFilesystem:   ptrBool(!p.WritableRootFilesystem),
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	if p.Privileged {
		sc.Privileged = ptrBool(true)
	}
	if p.SeccompUnconfined {
		sc.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
	}
	if p.KeepDefaultCapabilities {
		if len(p.AddCapabilities) > 0 {
			sc.Capabilities = &corev1.Capabilities{Add: p.AddCapabilities}
		}
	} else {
		sc.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: p.AddCapabilities}
	}
	if p.AllowRunAsRoot {
		sc.RunAsNonRoot = ptrBool(false)
		sc.RunAsUser = p.RunAsUser // nil = image default
	} else {
		uid := int64(1000)
		if p.RunAsUser != nil && *p.RunAsUser != 0 {
			uid = *p.RunAsUser
		}
		sc.RunAsNonRoot = ptrBool(true)
		sc.RunAsUser = &uid
	}
	return sc
}

// hardenPod applies pod-level defaults every lab pod gets regardless of profile:
// no service-account token (nothing here talks to the API), RuntimeDefault seccomp,
// and no host namespaces (the zero value already keeps hostNetwork/PID/IPC off).
func hardenPod(spec *corev1.PodSpec) {
	spec.AutomountServiceAccountToken = ptrBool(false)
	if spec.SecurityContext == nil {
		spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
}

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
// base64url(HMAC-SHA256(CTF_FLAG_SECRET, flagService+salt))[:flagTokenLen].
// base64url is mixed-case alphanumeric (+ -_); the secret comes from env so both
// sides share one source of truth.
func hash(input string) string {
	h := hmac.New(sha256.New, []byte(flagSecret()))
	h.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:flagTokenLen]
}

// flagSecret and jwtSecret are DISTINCT keys (security review finding #1): the flag-
// derivation HMAC key and the workspace-token (HS256) key. Keeping them separate means
// a leak of the guard/token secret cannot forge flags, and a leaked flag secret cannot
// mint workspace tokens. Both fall back to the legacy shared CTF_SCHOOL_SECRET during
// migration — the controller and CTFd fall back identically, so flags/tokens never
// drift while a cluster is still on the single secret. Prod sets the split values.
func flagSecret() string {
	return firstNonEmpty(os.Getenv("CTF_FLAG_SECRET"), os.Getenv("CTF_SCHOOL_SECRET"), devSecretDefault)
}

func jwtSecret() string {
	return firstNonEmpty(os.Getenv("CTF_JWT_SECRET"), os.Getenv("CTF_SCHOOL_SECRET"), devSecretDefault)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// devSecretDefault is the compiled-in fallback used only for local dev. If it (or an
// empty value) is what a secret resolves to at runtime, the platform is misconfigured.
const devSecretDefault = "ctf-school-secret-key"

// ValidateSecrets is a fail-closed startup guard (security review #1/#2 follow-up): it
// refuses to run if the flag or JWT secret is unset or still the built-in dev default,
// so a deployment that forgot to wire the Secret can't silently fall back to a
// source-code-known key (which would make every flag and workspace token forgeable).
// Set CTF_ALLOW_DEV_SECRETS=true to permit the dev default for local `make run`.
func ValidateSecrets() error {
	if os.Getenv("CTF_ALLOW_DEV_SECRETS") == "true" {
		return nil
	}
	for name, val := range map[string]string{"CTF_FLAG_SECRET": flagSecret(), "CTF_JWT_SECRET": jwtSecret()} {
		if val == "" || val == devSecretDefault {
			return fmt.Errorf("%s is unset or the built-in dev default; set a real secret (or a real CTF_SCHOOL_SECRET), "+
				"or set CTF_ALLOW_DEV_SECRETS=true for local dev", name)
		}
	}
	return nil
}

// vncPassword derives the desktop's VNC password per session — stable across reconciles
// (so it doesn't churn the pod), unique per session, and not a hardcoded literal. Our
// own desktop images ignore it; it only matters for the accetto fallback image.
func vncPassword(session *ctfcorev1.LabSession) string {
	mac := hmac.New(sha256.New, []byte(jwtSecret()))
	mac.Write([]byte("vnc-pw:" + session.Name))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:16]
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
