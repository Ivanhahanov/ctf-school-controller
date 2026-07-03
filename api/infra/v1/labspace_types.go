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

package v1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type WorkspaceType string

const (
	WorkspaceTerminal WorkspaceType = "Terminal"
	WorkspaceVSCode   WorkspaceType = "VSCode"
	WorkspaceNoVNC    WorkspaceType = "VNC"
)

// WorkspaceConfig описывает настройки интерфейса пользователя
type WorkspaceConfig struct {
	// Type указывает на тип интерфейса (например, Terminal)
	// +kubebuilder:validation:Enum=Terminal;VSCode;VNC
	Type WorkspaceType `json:"type"`
	// Image — кастомный образ
	// +optional
	Image string `json:"image,omitempty"`
	// Tasks — архив с заданиями
	// +optional
	Tasks string `json:"tasks,omitempty"`
	// Port is the port the workspace image serves its web UI (noVNC/ttyd) on.
	// Defaults to 6901 for VNC and 7681 for Terminal when unset.
	// +optional
	Port int32 `json:"port,omitempty"`

	// Security relaxes the desktop container's hardening. The current desktop images
	// initialise as root (useradd/chown, X11), so when this is absent the controller
	// applies a documented desktop default (root + writable rootfs + default caps),
	// while the guard sidecar and all challenge services stay fully locked down. Set
	// this to tighten further once the image can run rootless.
	// +optional
	Security *SecurityProfile `json:"security,omitempty"`

	// Resources sets the CPU/memory/ephemeral-storage requests and limits for the
	// desktop container. When unset the controller applies conservative defaults
	// (see the reconciler). The ephemeral-storage LIMIT is important: the desktop
	// runs with a writable root filesystem, so without it a runaway process could
	// fill node disk and trigger DiskPressure eviction across the node. Any field
	// left unset here is backfilled with the default for that field only.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// StorageLimit caps the size of the per-session /workspace scratch volume (an
	// emptyDir). Writes past it fail with ENOSPC on that volume instead of eating
	// the node's ephemeral storage. Defaults to 1Gi when unset.
	// +optional
	StorageLimit *resource.Quantity `json:"storageLimit,omitempty"`
}

// NetworkConfig defines the network isolation rules for the lab session.
type NetworkConfig struct {
	// AllowInternet toggles whether services in this space can access the public internet.
	// The controller should create corresponding Egress NetworkPolicies.
	// +kubebuilder:default=false
	AllowInternet bool `json:"allowInternet"`

	// InternalOnly restricts communication so that services can only talk to each other
	// within the same session namespace.
	// +kubebuilder:default=true
	InternalOnly bool `json:"internalOnly"`
}

// ResourceQuotaConfig defines the aggregate resource limits for the entire session namespace.
type ResourceQuotaConfig struct {
	// Requests defines the minimum guaranteed resources for the whole namespace.
	// +optional
	Requests corev1.ResourceList `json:"requests,omitempty"`

	// Limits defines the maximum resource consumption allowed for the whole namespace.
	// +optional
	Limits corev1.ResourceList `json:"limits,omitempty"`
}

// LabSpaceSpec defines the blueprint and global configuration for a lab environment.
// It acts as a template that aggregates multiple LabServices via selectors.
type LabSpaceSpec struct {
	// ServiceSelector is a label query over LabServices that should be part of this lab.
	// This allows dynamic inclusion of services based on challenge tags.
	ServiceSelector metav1.LabelSelector `json:"serviceSelector"`

	// Network defines the traffic isolation settings.
	Network NetworkConfig `json:"network"`

	// Resources defines the ResourceQuota for the session namespace.
	Resources ResourceQuotaConfig `json:"resources"`

	// Workspace определяет настройки рабочего окружения (терминал, папки)
	Workspace WorkspaceConfig `json:"workspace"`
	// DefaultTTL defines the session duration if not specified in LabSession (e.g., "2h", "30m").
	// +kubebuilder:validation:Pattern=`^([0-9]+h)?([0-9]+m)?([0-9]+s)?$`
	DefaultTTL string `json:"defaultTTL"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=labspaces,scope=Cluster

// LabSpace is the Schema for the labspaces API.
// It is Cluster-scoped as it represents a global infrastructure template for CTF challenges.
type LabSpace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the configuration and service discovery rules for the lab space.
	Spec LabSpaceSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// LabSpaceList contains a list of LabSpace.
type LabSpaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LabSpace `json:"items"`
}

func init() {
	SchemeBuilder.Register(&LabSpace{}, &LabSpaceList{})
}
