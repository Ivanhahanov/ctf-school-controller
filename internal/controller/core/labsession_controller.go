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
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	ctfcorev1 "ctf.school/controller/api/core/v1"
	infrav1 "ctf.school/controller/api/infra/v1"
	"golang.org/x/exp/rand"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
// +kubebuilder:rbac:groups="",resources=namespaces;pods;services,verbs=get;list;watch;create;update;patch;delete
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
		if err := r.reconcileRoute(ctx, targetNamespace, svcTemplate, session); err != nil {
			return ctrl.Result{}, err
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
	oldPhase := session.Status.Phase
	newPhase, newMsg := r.computePhase(podList)

	if oldPhase != newPhase {
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
	worksapceHost := fmt.Sprintf("http://workspace-%s-%s.%s", cleanDNSName(session.Spec.UserId), cleanDNSName(session.Spec.LabSpaceRef), domain)

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

	for _, svc := range svcs {
		if svc.Spec.Exposure != nil {
			addr := fmt.Sprintf("https://%s-%s.web.%s", svc.Name, session.Spec.UserId, domain)
			newEndpoints = append(newEndpoints, ctfcorev1.Endpoint{
				ServiceName: svc.Name,
				Type:        svc.Spec.Exposure.Type,
				Address:     addr,
			})
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

	requeueAfter := 5 * time.Second
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

func (r *LabSessionReconciler) computePhase(podList *corev1.PodList) (phase, message string) {
	if len(podList.Items) == 0 {
		return "Pending", "Starting infrastructure units..."
	}

	for _, pod := range podList.Items {
		// Init-контейнер ещё работает
		for _, s := range pod.Status.InitContainerStatuses {
			if s.Name == "provisioner" && s.State.Running != nil {
				return "Provisioning", "Downloading task assets..."
			}
		}

		if pod.Status.Phase != corev1.PodRunning {
			return "Pending", "Starting infrastructure units..."
		}

		// Проверяем Ready всех контейнеров — включая агента с его readinessProbe
		for _, cs := range pod.Status.ContainerStatuses {
			if !cs.Ready {
				return "Provisioning", "Preparing task environment..."
			}
		}
	}

	return "Running", "Lab ready."
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
func (r *LabSessionReconciler) reconcileWorkspaceRoute(ctx context.Context, ns string, space *infrav1.LabSpace, session *ctfcorev1.LabSession) error {
	domain := os.Getenv("CTF_DOMAIN")
	if domain == "" {
		domain = "ctf.school" // Дефолтное значение
	}

	// Очищаем имена для соответствия RFC 1123 (DNS Label)
	username := cleanDNSName(session.Spec.UserId)
	labname := cleanDNSName(session.Spec.LabSpaceRef)

	// Формируем домен по ТЗ: workspace-<username>-<labname>.<domain>
	vhost := fmt.Sprintf("workspace-%s-%s.%s", username, labname, domain)
	hostname := gatewayv1.Hostname(vhost)
	gatewayNS := gatewayv1.Namespace("gateway-system")

	targetPort := int32(7681) // по умолчанию ttyd
	if space.Spec.Workspace.Type == "VNC" {
		targetPort = int32(6901)
	}

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

		route.Spec.CommonRouteSpec.ParentRefs = []gatewayv1.ParentReference{{
			Name:      "external-gateway",
			Namespace: &gatewayNS,
		}}
		route.Spec.Hostnames = []gatewayv1.Hostname{hostname}
		route.Spec.Rules = []gatewayv1.HTTPRouteRule{{
			BackendRefs: []gatewayv1.HTTPBackendRef{
				{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName(workspaceSvcName),
							Port: (*gatewayv1.PortNumber)(ptrInt32(targetPort)), // Порт ttyd по умолчанию
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

	// Собираем контейнеры динамически
	containers := []corev1.Container{
		r.buildWorkspaceInterface(space, tasks, session),
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
			Volumes:    volumes,
			Containers: containers,
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

		// Настраиваем порты динамически
		if space.Spec.Workspace.Type == "VNC" {
			svc.Spec.Ports = []corev1.ServicePort{
				{
					Name:       "novnc",
					Port:       6901,
					TargetPort: intstr.FromInt(6901),
				},
			}
		} else {
			svc.Spec.Ports = []corev1.ServicePort{
				{
					Name:       "ttyd",
					Port:       7681,
					TargetPort: intstr.FromInt(7681),
				},
			}
			// Добавляем чекер, только если он есть (не VNC)
			svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
				Name: "checker",
				Port: 8888,
			})
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
		Name:       "interface",
		Image:      image,
		WorkingDir: "/workspace",
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
			Containers: []corev1.Container{
				{
					Name:            "challenge",
					Image:           labSvc.Spec.Image,
					ImagePullPolicy: labSvc.Spec.ImagePullPolicy,
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

	// 3. Создаем Service для доступа внутри кластера
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

	hostname := gatewayv1.Hostname(fmt.Sprintf("%s-%s.web.ctf.school", labSvc.Name, session.Spec.UserId))
	gatewayNS := gatewayv1.Namespace("gateway-system") // создаем переменную типа

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      labSvc.Name,
			Namespace: ns,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, route, func() error {
		route.Spec.CommonRouteSpec.ParentRefs = []gatewayv1.ParentReference{{
			Name:      "external-gateway",
			Namespace: &gatewayNS, // передаем указатель на типизированную переменную
		}}
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

func (r *LabSessionReconciler) buildEnvVars(labSvc *infrav1.LabService, session *ctfcorev1.LabSession) []corev1.EnvVar {
	var result []corev1.EnvVar

	for _, e := range labSvc.Spec.Env {
		val := e.Value

		if e.DynamicValue != nil {
			switch e.DynamicValue.Type {
			case "random":
				val = generateRandomString(e.DynamicValue.Length)
			case "hmac":
				// Генерируем флаг на основе UserId и секрета системы
				val = fmt.Sprintf(e.DynamicValue.Template, hash(labSvc.Name+session.Spec.UserId))
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
func hash(input string) string {
	secret := "ctf-school-secret-key" // В продакшене брать из ENV или Secret
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))[:12] // Берем первые 12 символов для компактности
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
