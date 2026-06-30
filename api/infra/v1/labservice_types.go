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

// DynamicValue defines logic for generating session-specific secrets (e.g. flags or passwords).
type DynamicValue struct {
	// Type defines the generation strategy. Supported: "random", "hmac".
	// +kubebuilder:validation:Enum=random;hmac
	Type string `json:"type"`

	// Length specifies the character count for "random" type generation.
	// +optional
	Length int `json:"length,omitempty"`

	// Template is a format string for "hmac" or "random" results (e.g., "CTF{%s}").
	// +optional
	Template string `json:"template,omitempty"`
}

// EnvVar defines a custom environment variable, which can be static or dynamically generated.
type EnvVar struct {
	// Name of the environment variable. Must be a C_IDENTIFIER.
	Name string `json:"name"`

	// Value is a static string value.
	// +optional
	Value string `json:"value,omitempty"`

	// DynamicValue defines how to generate a unique value for this variable per session.
	// +optional
	DynamicValue *DynamicValue `json:"dynamicValue,omitempty"`
}

// Exposure defines how the LabService is presented to the user via the gateway.
type Exposure struct {
	// Type defines the protocol and UI handling (HTTP, GRPC, Terminal, VNC).
	// +kubebuilder:validation:Enum=HTTP;GRPC;Terminal;VNC
	Type string `json:"type"`

	// TargetPort is the name (preferred) or number of the port in the container to expose.
	TargetPort string `json:"targetPort"`
}

// EgressPort restricts an EgressRule to a specific destination port/protocol.
type EgressPort struct {
	// Protocol is TCP or UDP. Defaults to TCP.
	// +kubebuilder:validation:Enum=TCP;UDP
	// +kubebuilder:default=TCP
	// +optional
	Protocol corev1.Protocol `json:"protocol,omitempty"`

	// Port is the destination port number.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// EgressRule allow-lists outbound traffic from a single LabService to a specific
// external destination. Rules are additive and scoped to this service's pods only,
// so one challenge can be granted a single API without opening the whole internet.
type EgressRule struct {
	// FQDNs is a list of DNS names the service may reach, e.g. "api.deepseek.com".
	// A leading "*." wildcard is supported ("*.googleapis.com"). Enforced via the
	// Cilium toFQDNs mechanism, which requires the Cilium CNI.
	// +optional
	FQDNs []string `json:"fqdns,omitempty"`

	// CIDRs is a list of IP ranges the service may reach, e.g. "203.0.113.0/24".
	// +optional
	CIDRs []string `json:"cidrs,omitempty"`

	// Ports restricts this rule to specific destination ports. Empty means all ports.
	// +optional
	Ports []EgressPort `json:"ports,omitempty"`
}

// LabServiceSpec defines the blueprint for a specific lab component.
// Since this is a Cluster-scoped resource, it acts as a global template.
type LabServiceSpec struct {
	// Image is the Docker image repository and tag.
	// +kubebuilder:validation:Required
	Image string `json:"image"`

	// ImagePullPolicy defines when to pull the image (Always, IfNotPresent, Never).
	// +optional
	// +kubebuilder:default=IfNotPresent
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// Ports defines the list of network ports to be opened in the container.
	// +optional
	Ports []corev1.ContainerPort `json:"ports,omitempty"`

	// LivenessProbe describes when to restart the container using standard K8s probe logic.
	// +optional
	Liveness *corev1.Probe `json:"liveness,omitempty"`

	// ReadinessProbe describes when the container is ready to accept traffic.
	// +optional
	Readiness *corev1.Probe `json:"readiness,omitempty"`

	// Exposure defines how this service should be reached from the outside world.
	// +optional
	Exposure *Exposure `json:"exposure"`

	// Env is a list of environment variables to set in the container.
	// +optional
	Env []EnvVar `json:"env,omitempty"`

	// Command overrides the container entrypoint.
	// +optional
	Command []string `json:"command,omitempty"`

	// Args are the arguments passed to the command.
	// +optional
	Args []string `json:"args,omitempty"`

	// Resources defines CPU and Memory constraints for this service.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Egress is a per-service allow-list of external destinations this service may
	// reach. It is additive on top of the LabSpace network policy and is scoped to
	// this service's pods only: when empty the service gets no outbound internet
	// access. Use it to grant a single API (e.g. DeepSeek) instead of opening the
	// whole internet via LabSpace.Network.AllowInternet. Requires the Cilium CNI.
	// +optional
	Egress []EgressRule `json:"egress,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=labservices,scope=Cluster

// LabService is the Schema for the labservices API.
// It is Cluster-scoped because it serves as a global infrastructure definition.
type LabService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the configuration of the service blueprint.
	Spec LabServiceSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// LabServiceList contains a list of LabService.
type LabServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LabService `json:"items"`
}

func init() {
	SchemeBuilder.Register(&LabService{}, &LabServiceList{})
}
