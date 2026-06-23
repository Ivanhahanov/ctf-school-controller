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

package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	eduv1 "ctf.school/controller/api/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// CTFTaskReconciler reconciles a CTFTask object
type CTFTaskReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=edu.ctf.school,resources=ctftasks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=edu.ctf.school,resources=ctftasks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=edu.ctf.school,resources=ctftasks/finalizers,verbs=update
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods;services,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the CTFTask object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.1/pkg/reconcile
func (r *CTFTaskReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := logf.FromContext(ctx)

	var task eduv1.CTFTask
	if err := r.Get(ctx, req.NamespacedName, &task); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// --- 1. Проверка TTL (Удаление) ---
	if task.Status.ExpiryTime != nil && time.Now().After(task.Status.ExpiryTime.Time) {
		l.Info("Lab expired, deleting...")
		return ctrl.Result{}, r.Delete(ctx, &task)
	}

	// --- 2. Инициализация (Первый запуск) ---
	if task.Status.Phase == "" {
		duration, _ := time.ParseDuration(task.Spec.Duration)
		expiry := metav1.NewTime(time.Now().Add(duration))

		task.Status.ExpiryTime = &expiry
		task.Status.Phase = "Pending"
		task.Status.Message = "Creating challenge resources..."
		if err := r.Status().Update(ctx, &task); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// --- 3. Provisioning (Создание ресурсов) ---
	// Если мы в Pending, начинаем создавать ресурсы и переходим в Provisioning
	if task.Status.Phase == "Pending" {
		task.Status.Phase = "Provisioning"
		if err := r.Status().Update(ctx, &task); err != nil {
			return ctrl.Result{}, err
		}
	}

	// --- 4. Синхронизация ресурсов ---
	masterSalt := os.Getenv("LAB_MASTER_SALT")
	expectedFlag := r.generateFlag(&task, masterSalt)

	if err := r.ensureResources(ctx, &task, expectedFlag); err != nil {
		// Если произошла ошибка при создании ресурсов
		task.Status.Phase = "Failed"
		task.Status.Message = err.Error()
		_ = r.Status().Update(ctx, &task)
		return ctrl.Result{}, err
	}

	// --- 5. Проверка готовности (Check Ready) ---
	// Теперь проверяем, поднялся ли реально Под
	podReady, err := r.isPodReady(ctx, &task)
	if err != nil {
		return ctrl.Result{}, err
	}

	oldPhase := task.Status.Phase
	if podReady {
		task.Status.Phase = "Ready"
		task.Status.Endpoint = fmt.Sprintf("https://%s.labs.ctf.school", task.Name)
		task.Status.Message = "All systems go"
	} else {
		// Если ресурсы созданы, но под еще не Ready
		task.Status.Phase = "Provisioning"
		task.Status.Message = "Waiting for container to start..."
	}

	// Обновляем статус только если фаза изменилась, чтобы не зацикливаться
	if oldPhase != task.Status.Phase {
		if err := r.Status().Update(ctx, &task); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *CTFTaskReconciler) isPodReady(ctx context.Context, task *eduv1.CTFTask) (bool, error) {
	pod := &corev1.Pod{}
	err := r.Get(ctx, client.ObjectKey{Namespace: task.Namespace, Name: task.Name}, pod)
	if err != nil {
		return false, client.IgnoreNotFound(err)
	}

	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true, nil
		}
	}
	return false, nil
}

// generateFlag вычисляет HMAC на основе параметров из Spec
func (r *CTFTaskReconciler) generateFlag(task *eduv1.CTFTask, salt string) string {
	h := hmac.New(sha256.New, []byte(salt))

	data := task.Name // Global scope по умолчанию
	if task.Spec.FlagConfig.Scope == "Personal" {
		data = fmt.Sprintf("%s-%s", task.Name, task.Spec.StudentID)
	}

	h.Write([]byte(data))
	hash := hex.EncodeToString(h.Sum(nil))

	length := task.Spec.FlagConfig.Length
	if length == 0 {
		length = 12
	}

	return fmt.Sprintf(task.Spec.FlagConfig.Format, hash[:length])
}

func (r *CTFTaskReconciler) ensureResources(ctx context.Context, task *eduv1.CTFTask, flag string) error {

	// 1. Manage the Pod (The environment)
	if err := r.ensurePod(ctx, task, flag); err != nil {
		return fmt.Errorf("failed to ensure pod: %w", err)
	}

	// 2. Manage the Service (Internal networking)
	if err := r.ensureService(ctx, task); err != nil {
		return fmt.Errorf("failed to ensure service: %w", err)
	}

	// 3. Manage the NetworkPolicy (Security isolation)
	// CALL IT HERE
	if err := r.ensureNetworkPolicy(ctx, task); err != nil {
		return fmt.Errorf("failed to ensure network policy: %w", err)
	}

	// 4. Manage the HTTPRoute (External access via API Gateway)
	// if err := r.ensureHTTPRoute(ctx, task); err != nil {
	// 	return fmt.Errorf("failed to ensure http route: %w", err)
	// }

	return nil
}

func (r *CTFTaskReconciler) ensurePod(ctx context.Context, task *eduv1.CTFTask, flag string) error {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: task.Name, Namespace: task.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, pod, func() error {
		pod.Labels = map[string]string{
			"app":        "ctf-task",
			"task-name":  task.Name,
			"student-id": task.Spec.StudentID,
		}

		// Pod specs are mostly immutable; define them only during initial creation
		if pod.CreationTimestamp.IsZero() {
			pod.Spec.Containers = []corev1.Container{{
				Name:  "challenge",
				Image: task.Spec.Image,
				Ports: []corev1.ContainerPort{{ContainerPort: task.Spec.Port}},
				// Inject the generated HMAC flag via Environment Variable
				Env: []corev1.EnvVar{{Name: "FLAG", Value: flag}},
			}}
		}
		// Set owner reference so the Pod is deleted when CTFTask is removed
		return ctrl.SetControllerReference(task, pod, r.Scheme)

	})
	return err
}
func (r *CTFTaskReconciler) ensureService(ctx context.Context, task *eduv1.CTFTask) error {
	//  Reconcile Service: Internal load balancer for the Pod
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: task.Name, Namespace: task.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Spec.Selector = map[string]string{"task-name": task.Name}
		svc.Spec.Ports = []corev1.ServicePort{{
			Protocol:   corev1.ProtocolTCP,
			Port:       80,
			TargetPort: intstr.FromInt(int(task.Spec.Port)),
		}}
		return ctrl.SetControllerReference(task, svc, r.Scheme)
	})
	return err
}
func (r *CTFTaskReconciler) ensureHTTPRoute(ctx context.Context, task *eduv1.CTFTask) error {
	// Reconcile HTTPRoute: Map the Gateway traffic to the Service
	route := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: task.Name, Namespace: task.Namespace}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, route, func() error {
		hostname := gatewayv1.Hostname(fmt.Sprintf("%s.labs.ctf.school", task.Name))

		route.Spec = gatewayv1.HTTPRouteSpec{
			// Attach this route to a pre-existing Gateway named 'external-web'
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{
					Name:      "external-web",
					Namespace: ptrTo(gatewayv1.Namespace("gateway-system")),
				}},
			},
			Hostnames: []gatewayv1.Hostname{hostname},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName(task.Name),
							Port: ptrTo(gatewayv1.PortNumber(80)),
						},
					},
				}},
			}},
		}
		return ctrl.SetControllerReference(task, route, r.Scheme)
	})
	return err
}

func (r *CTFTaskReconciler) ensureNetworkPolicy(ctx context.Context, task *eduv1.CTFTask) error {
	netPol := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      task.Name,
			Namespace: task.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, netPol, func() error {
		// Define which pods this policy applies to
		netPol.Spec = networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"task-name": task.Name,
				},
			},
			// Apply rules to both incoming and outgoing traffic
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},

			// INGRESS: Allow traffic ONLY from the API Gateway
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							// Target the namespace where your API Gateway lives
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "gateway-system",
								},
							},
							// Optional: Target specific Gateway pods by label
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "gateway-api-controller",
								},
							},
						},
					},
				},
			},

			// EGRESS: Strict isolation for the challenge environment
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								// Allow general Internet access (e.g., for updates/curls)
								CIDR: "0.0.0.0/0",
								Except: []string{
									"169.254.169.254/32", // Block Cloud Instance Metadata (IMDS)
									"10.0.0.0/8",         // Block Internal Cluster Network (Class A)
									"172.16.0.0/12",      // Block Internal Cluster Network (Class B)
									"192.168.0.0/16",     // Block Internal Cluster Network (Class C)
								},
							},
						},
					},
				},
				// Allow DNS resolution (Required for the app to function)
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"k8s-app": "kube-dns",
								},
							},
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "kube-system",
								},
							},
						},
					},
				},
			},
		}

		// Bind life-cycle to the parent CTFTask
		return ctrl.SetControllerReference(task, netPol, r.Scheme)
	})

	return err
}

// SetupWithManager sets up the controller with the Manager.
func (r *CTFTaskReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&eduv1.CTFTask{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.Service{}).
		Named("ctftask").
		Complete(r)
}

func ptrTo[T any](v T) *T {
	return &v
}
