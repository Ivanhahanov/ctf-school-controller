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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// LabSessionSpec defines the desired state of a user's lab instance.
type LabSessionSpec struct {
	// UserId is the unique identifier of the student/user who owns this session.
	// +kubebuilder:validation:Required
	UserId string `json:"userId"`

	// LabSpaceRef is the name of the Cluster-scoped LabSpace template to instantiate.
	// +kubebuilder:validation:Required
	LabSpaceRef string `json:"labSpaceRef"`
}

// Endpoint represents a network entry point for the user to interact with the lab.
type Endpoint struct {
	// ServiceName refers to the name of the LabService within the session.
	ServiceName string `json:"serviceName"`

	// Type defines the protocol/access method (e.g., HTTP, Terminal, GRPC, VNC).
	// +kubebuilder:validation:Enum=HTTP;Terminal;GRPC;VNC
	Type string `json:"type"`

	// Address is the fully qualified domain name or IP with optional port/protocol.
	Address string `json:"address"`
}

// LabSessionStatus defines the observed state of the LabSession.
type LabSessionStatus struct {
	// Phase is a high-level summary of the session lifecycle.
	// +kubebuilder:validation:Enum=Pending;Running;Failed;Terminating;Expired
	// +kubebuilder:default=Pending
	Phase string `json:"phase,omitempty"`

	// Conditions represent the detailed state transitions of the session.
	// Common types: InfrastructureReady, ServicesHealthy, Ready.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// Message
	// +optional
	Message string `json:"message,omitempty"`

	// Summary
	// +optional
	Summary SessionSummary `json:"summary,omitempty"`

	// Endpoints lists all public-facing addresses for the lab services.
	// +optional
	Endpoints []Endpoint `json:"endpoints,omitempty"`

	// StartTime is the moment the lab infrastructure became Ready.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// ExpiredTime is the calculated or actual moment when the session is/was terminated.
	// +optional
	ExpiredTime *metav1.Time `json:"expiredTime,omitempty"`
}

type SessionSummary struct {
	ActiveServices int    `json:"activeServices"`
	TotalServices  int    `json:"totalServices"`
	Namespace      string `json:"namespace"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=labsessions,scope=Cluster
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="User",type="string",JSONPath=".spec.userId"
// +kubebuilder:printcolumn:name="Lab",type="string",JSONPath=".spec.labSpaceRef"
// +kubebuilder:printcolumn:name="Expires",type="string",JSONPath=".status.expiredTime"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.message"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// LabSession is the Schema for the labsessions API, representing an active lab instance.
type LabSession struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the configuration of the session.
	Spec LabSessionSpec `json:"spec"`

	// Status defines the current state of the session.
	// +optional
	Status LabSessionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// LabSessionList contains a list of LabSession.
type LabSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []LabSession `json:"items"`
}

func init() {
	SchemeBuilder.Register(&LabSession{}, &LabSessionList{})
}
