package iac

import "testing"

const benchK8s = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext:
            privileged: false
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "250m"
              memory: "128Mi"
`

func BenchmarkScanIaC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = LintKubernetesYAML(benchK8s, "file://deployment.yaml")
	}
}
