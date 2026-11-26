package fix

import (
	"strings"
	"testing"

	"github.com/luminariadev/raksa-pipeguard/internal/ciworkflow"
	"github.com/luminariadev/raksa-pipeguard/internal/iac"
)

func TestSuggestFixesDockerfileK8sAndGitHubActions(t *testing.T) {
	// 1. Dockerfile fix adds nonroot USER and tightens chmod 777.
	dfIn := "FROM alpine:3.21.3\nRUN chmod 777 /app\nCMD [\"/app/srv\"]\n"
	dfRes, err := SuggestFixes(dfIn, "dockerfile", "Dockerfile")
	if err != nil || !dfRes.Changed {
		t.Fatalf("Dockerfile fix failed: err=%v res=%+v", err, dfRes)
	}
	if hits := iac.LintDockerfile(dfRes.Patched, "file://Dockerfile"); len(hits) != 0 {
		t.Fatalf("expected patched Dockerfile to have 0 IaC findings, got %+v\npatched:\n%s", hits, dfRes.Patched)
	}

	// 2. Kubernetes fix hardens container securityContext & limits to 0 findings.
	k8sIn := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: web
          image: nginx:1.25
          securityContext:
            privileged: true
`
	k8sRes, err := SuggestFixes(k8sIn, "kubernetes", "deployment.yaml")
	if err != nil || !k8sRes.Changed {
		t.Fatalf("K8s fix failed: err=%v res=%+v", err, k8sRes)
	}
	if hits := iac.LintKubernetesYAML(k8sRes.Patched, "file://deployment.yaml"); len(hits) != 0 {
		t.Fatalf("expected patched K8s YAML to have 0 findings, got %+v\npatched:\n%s", hits, k8sRes.Patched)
	}

	// 3. GitHub Actions fix removes pull_request_target, adds permissions, and moves PR title to env.
	ghIn := `name: PR Check
on:
  pull_request_target:
    types: [opened]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "PR=${{ github.event.pull_request.title }}"
`
	ghRes, err := SuggestFixes(ghIn, "github-actions", ".github/workflows/pr.yml")
	if err != nil || !ghRes.Changed {
		t.Fatalf("GitHub Actions fix failed: err=%v res=%+v", err, ghRes)
	}
	if hits, err := ciworkflow.ScanContent(ghRes.Patched, ".github/workflows/pr.yml"); err != nil || len(hits) != 0 {
		t.Fatalf("expected patched GitHub workflow to have 0 findings, got hits=%+v err=%v\npatched:\n%s", hits, err, ghRes.Patched)
	}
	if !strings.Contains(ghRes.Diff, "--- a/.github/workflows/pr.yml") {
		t.Fatalf("expected unified diff header, got:\n%s", ghRes.Diff)
	}
}
