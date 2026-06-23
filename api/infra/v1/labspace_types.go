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
