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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// CTFTaskSpec defines the desired state of CTFTask
type CTFTaskSpec struct {
	// Image — это Docker образ с заданием.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`

	// Port — порт приложения внутри контейнера.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// StudentID — уникальный идентификатор студента (для HMAC генерации).
	// +kubebuilder:validation:Required
	StudentID string `json:"studentId"`

	// Duration — время жизни лабы в формате Duration (например, 1h, 30m).
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern=`^([0-9]+(h|m|s))+$`
	// +kubebuilder:default="1h"
	Duration string `json:"duration"`

	// FlagConfig — настройки генерации флага.
	// +kubebuilder:validation:Required
	FlagConfig FlagConfig `json:"flagConfig"`
}

type FlagConfig struct {
	// Format — шаблон флага. Должен содержать %s для подстановки хэша.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^.*%s.*$`
	// +kubebuilder:default="FLAG{%s}"
	Format string `json:"format"`

	// Scope определяет уникальность флага.
	// +kubebuilder:validation:Enum=Global;Personal
	// +kubebuilder:default=Personal
	Scope string `json:"scope"`

	// Length — длина генерируемой хэш-части.
	// +kubebuilder:validation:Minimum=8
	// +kubebuilder:validation:Maximum=64
	// +kubebuilder:default=12
	Length int `json:"length,omitempty"`
}

// CTFTaskStatus defines the observed state of CTFTask.
// +kubebuilder:subresource:status
type CTFTaskStatus struct {
	// Phase - описывает текущую стадию жизненного цикла задания.
	// +kubebuilder:validation:Enum=Provisioning;Pending;Active;Ready;Solved;Expired;Failed
	// +kubebuilder:default=Pending
	Phase string `json:"phase"`

	// Message - information
	// +optional
	Message string `json:"message"`
	// Endpoint — URL или IP, по которому студент обращается к заданию.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// ExpiryTime — расчетное время удаления ресурсов лабы.
	// +optional
	ExpiryTime *metav1.Time `json:"expiryTime,omitempty"`

	// SolvedAt — время, когда был успешно проверен флаг.
	// +optional
	SolvedAt *metav1.Time `json:"solvedAt,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase",description="Current phase of the lab"
// +kubebuilder:printcolumn:name="Student",type="string",JSONPath=".spec.studentId",description="Owner of the lab"
// +kubebuilder:printcolumn:name="Expires",type="string",JSONPath=".status.expiryTime",description="Time when lab will be deleted"
// +kubebuilder:printcolumn:name="Endpoint",type="string",JSONPath=".status.endpoint"
// CTFTask is the Schema for the ctftasks API
type CTFTask struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of CTFTask
	// +required
	Spec CTFTaskSpec `json:"spec"`

	// status defines the observed state of CTFTask
	// +optional
	Status CTFTaskStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CTFTaskList contains a list of CTFTask
type CTFTaskList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CTFTask `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CTFTask{}, &CTFTaskList{})
}
