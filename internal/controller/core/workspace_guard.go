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
	"fmt"
	"os"

	ctfcorev1 "ctf.school/controller/api/core/v1"
	infrav1 "ctf.school/controller/api/infra/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

const guardPort int32 = 8080

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// guardImage is the per-session Go guard image (authorizes the team-scoped token,
// injects the anti-AI watermark, reverse-proxies to the desktop). Configurable via
// GUARD_IMAGE so each cluster pulls it from its own registry (local: the kind-loaded
// `ctf-school/guard:latest`; prod: e.g. docker.io/explabs/ctf-school-guard:<ver>).
func guardImage() string {
	return envDefault("GUARD_IMAGE", "explabs/ctf-school-guard:latest")
}

// workspaceWebPort returns the port the desktop image serves its web UI on.
func workspaceWebPort(space *infrav1.LabSpace) int32 {
	if space.Spec.Workspace.Port != 0 {
		return space.Spec.Workspace.Port
	}
	if space.Spec.Workspace.Type == infrav1.WorkspaceNoVNC {
		return 6901
	}
	return 7681
}

// guardSidecar fronts the desktop. It enforces the team-scoped `lab_auth` token
// (so players cannot reach another team's workspace) and injects the watermark.
// The desktop image itself is unchanged.
func guardSidecar(space *infrav1.LabSpace, session *ctfcorev1.LabSession) corev1.Container {
	scheme := envDefault("CTF_SCHEME", "http")
	domain := envDefault("CTF_DOMAIN", "ctf.school")
	// The guard validates workspace HS256 tokens — it gets the JWT secret, NOT the flag
	// secret (finding #1: a guard compromise must not be able to forge flags).
	secret := jwtSecret()
	// Unauthenticated navigations are bounced back to CTFd, which re-mints the
	// cookie when the player re-opens the lab.
	loginURL := fmt.Sprintf("%s://%s/challenges", scheme, domain)

	return corev1.Container{
		Name:            "workspace-guard",
		Image:           guardImage(),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports:           []corev1.ContainerPort{{Name: "web", ContainerPort: guardPort}},
		// Fully locked down: the guard is a static Go binary (distroless nonroot) that
		// binds :8080 and reads nothing from disk — no relaxation needed.
		SecurityContext: containerSecurityContext(nil),
		// The guard is a lightweight reverse proxy — pin it small so the namespace
		// ResourceQuota budget goes to the desktop, not to the LimitRange default.
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("10m"),
				corev1.ResourceMemory:           resource.MustParse("32Mi"),
				corev1.ResourceEphemeralStorage: guardEphemeralRequest.DeepCopy(),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("200m"),
				corev1.ResourceMemory:           resource.MustParse("128Mi"),
				corev1.ResourceEphemeralStorage: guardEphemeralLimit.DeepCopy(),
			},
		},
		Env: []corev1.EnvVar{
			{Name: "GUARD_UPSTREAM", Value: fmt.Sprintf("127.0.0.1:%d", workspaceWebPort(space))},
			{Name: "GUARD_TEAM", Value: session.Spec.UserId},
			{Name: "GUARD_SID", Value: session.Name},
			{Name: "GUARD_LABSPACE", Value: session.Spec.LabSpaceRef}, // challenge → joins guard ↔ CTFd metrics
			{Name: "GUARD_SECRET", Value: secret},
			{Name: "GUARD_LOGIN_URL", Value: loginURL},
			// Propagate the dev-secret opt-in so the guard's fail-closed check agrees
			// with the controller's when running in local dev mode.
			{Name: "CTF_ALLOW_DEV_SECRETS", Value: os.Getenv("CTF_ALLOW_DEV_SECRETS")},
		},
	}
}
