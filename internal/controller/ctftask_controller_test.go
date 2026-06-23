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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	eduv1 "ctf.school/controller/api/v1"
)

var _ = Describe("CTFTask Controller", func() {
	const (
		TaskName   = "sqli-challenge"
		Namespace  = "default"
		StudentID  = "student-uuid-123"
		MasterSalt = "super-secret-salt"
	)

	BeforeEach(func() {
		os.Setenv("LAB_MASTER_SALT", MasterSalt)
	})

	Context("When creating a new CTFTask", func() {
		It("Should create all sub-resources with correct configuration", func() {
			By("Creating the CTFTask object")
			task := &eduv1.CTFTask{
				ObjectMeta: metav1.ObjectMeta{
					Name:      TaskName,
					Namespace: Namespace,
				},
				Spec: eduv1.CTFTaskSpec{
					Image:     "nginx",
					Port:      8080,
					StudentID: StudentID,
					Duration:  "1h",
					FlagConfig: eduv1.FlagConfig{
						Format: "CTF{%s}",
						Scope:  "Personal",
						Length: 10,
					},
				},
			}
			Expect(k8sClient.Create(ctx, task)).Should(Succeed())

			// 1. Проверяем переход в фазу Active
			By("Checking if Status becomes Active")
			lookupKey := types.NamespacedName{Name: TaskName, Namespace: Namespace}
			createdTask := &eduv1.CTFTask{}
			Eventually(func() string {
				_ = k8sClient.Get(ctx, lookupKey, createdTask)
				return createdTask.Status.Phase
			}, time.Second*10, time.Millisecond*500).Should(Equal("Active"))

			// 2. Проверяем наличие Пода и корректность Флага
			By("Verifying the Pod and HMAC Flag")
			pod := &corev1.Pod{}
			Eventually(func() error {
				return k8sClient.Get(ctx, lookupKey, pod)
			}, time.Second*10).Should(Succeed())

			// Вычисляем ожидаемый HMAC вручную для сверки
			h := hmac.New(sha256.New, []byte(MasterSalt))
			h.Write([]byte(fmt.Sprintf("%s-%s", TaskName, StudentID)))
			expectedHash := hex.EncodeToString(h.Sum(nil))[:10]
			expectedFlag := fmt.Sprintf("CTF{%s}", expectedHash)

			Expect(pod.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{
				Name:  "FLAG",
				Value: expectedFlag,
			}))

			// 3. Проверяем создание NetworkPolicy
			By("Verifying NetworkPolicy isolation")
			netPol := &networkingv1.NetworkPolicy{}
			Expect(k8sClient.Get(ctx, lookupKey, netPol)).Should(Succeed())
			Expect(netPol.Spec.PodSelector.MatchLabels["task-name"]).To(Equal(TaskName))
		})
	})
})

var _ = Describe("CTFTask TTL Logic", func() {
	const (
		TaskName  = "ttl-test-lab"
		Namespace = "default"
	)

	Context("When the lab duration has passed", func() {
		It("Should transition the phase to Expired", func() {
			By("Creating a CTFTask with 1 second duration")
			task := &eduv1.CTFTask{
				ObjectMeta: metav1.ObjectMeta{
					Name:      TaskName,
					Namespace: Namespace,
				},
				Spec: eduv1.CTFTaskSpec{
					Image:     "nginx",
					Port:      80,
					Duration:  "1s", // Очень короткое время
					StudentID: "student-1",
					FlagConfig: eduv1.FlagConfig{
						Format: "FLAG{%s}",
						Scope:  "Personal",
					},
				},
			}
			Expect(k8sClient.Create(ctx, task)).Should(Succeed())

			// 1. Ждем, когда контроллер инициализирует ExpiryTime и сделает задачу Active
			lookupKey := types.NamespacedName{Name: TaskName, Namespace: Namespace}
			Eventually(func() string {
				_ = k8sClient.Get(ctx, lookupKey, task)
				return task.Status.Phase
			}, time.Second*5).Should(Equal("Active"))

			// 2. Ждем чуть больше секунды, чтобы время истекло
			time.Sleep(2 * time.Second)

			// 3. Проверяем, что контроллер при следующем проходе увидел истечение
			By("Checking if the phase is now Expired")
			Eventually(func() string {
				_ = k8sClient.Get(ctx, lookupKey, task)
				return task.Status.Phase
			}, time.Second*10).Should(Equal("Expired"))
		})
	})
})
