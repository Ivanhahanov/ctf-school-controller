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
)

const (
	// guardImage is the per-session Go guard: it authorizes requests (team-scoped
	// token), injects the anti-AI watermark, and reverse-proxies to the desktop.
	guardImage      = "ctf-school-guard:latest"
	guardPort int32 = 8080
)

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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
	secret := envDefault("CTF_SCHOOL_SECRET", "ctf-school-secret-key")
	// Unauthenticated navigations are bounced back to CTFd, which re-mints the
	// cookie when the player re-opens the lab.
	loginURL := fmt.Sprintf("%s://%s/challenges", scheme, domain)

	return corev1.Container{
		Name:            "workspace-guard",
		Image:           guardImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports:           []corev1.ContainerPort{{Name: "web", ContainerPort: guardPort}},
		Env: []corev1.EnvVar{
			{Name: "GUARD_UPSTREAM", Value: fmt.Sprintf("127.0.0.1:%d", workspaceWebPort(space))},
			{Name: "GUARD_TEAM", Value: session.Spec.UserId},
			{Name: "GUARD_SID", Value: session.Name},
			{Name: "GUARD_SECRET", Value: secret},
			{Name: "GUARD_LOGIN_URL", Value: loginURL},
		},
	}
}
