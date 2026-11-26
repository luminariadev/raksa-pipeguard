package iac

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
	"gopkg.in/yaml.v3"
)

type k8sDoc struct {
	Kind string `yaml:"kind"`
	Spec struct {
		Template struct {
			Spec k8sPodSpec `yaml:"spec"`
		} `yaml:"template"`
		JobTemplate struct {
			Spec struct {
				Template struct {
					Spec k8sPodSpec `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		} `yaml:"jobTemplate"`
		k8sPodSpec `yaml:",inline"`
	} `yaml:"spec"`
}

type k8sPodSpec struct {
	HostNetwork     bool           `yaml:"hostNetwork"`
	HostPID         bool           `yaml:"hostPID"`
	HostIPC         bool           `yaml:"hostIPC"`
	SecurityContext *k8sPodSecCtx  `yaml:"securityContext"`
	Containers      []k8sContainer `yaml:"containers"`
	InitContainers  []k8sContainer `yaml:"initContainers"`
}

type k8sPodSecCtx struct {
	RunAsNonRoot *bool  `yaml:"runAsNonRoot"`
	RunAsUser    *int64 `yaml:"runAsUser"`
}

type k8sContainer struct {
	Name            string                `yaml:"name"`
	SecurityContext *k8sContainerSecCtx   `yaml:"securityContext"`
	Resources       *k8sResourceReqLimits `yaml:"resources"`
}

type k8sContainerSecCtx struct {
	Privileged               *bool  `yaml:"privileged"`
	RunAsNonRoot             *bool  `yaml:"runAsNonRoot"`
	RunAsUser                *int64 `yaml:"runAsUser"`
	AllowPrivilegeEscalation *bool  `yaml:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool  `yaml:"readOnlyRootFilesystem"`
	Capabilities             *struct {
		Drop []string `yaml:"drop"`
		Add  []string `yaml:"add"`
	} `yaml:"capabilities"`
}

type k8sResourceReqLimits struct {
	Limits map[string]any `yaml:"limits"`
}

func LooksLikeKubernetesYAML(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "kind:") {
			k := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "kind:")))
			if isK8sWorkloadKind(k) {
				return true
			}
		}
	}
	return false
}

func isK8sWorkloadKind(lowerKind string) bool {
	switch strings.Trim(lowerKind, `"'`) {
	case "pod", "deployment", "daemonset", "statefulset", "replicaset", "job", "cronjob":
		return true
	default:
		return false
	}
}

func LintKubernetesYAML(content string, target string) []schema.Finding {
	dec := yaml.NewDecoder(strings.NewReader(content))
	now := time.Now().UTC()
	var findings []schema.Finding
	docIdx := 0

	for {
		var doc k8sDoc
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
		docIdx++
		kindLow := strings.ToLower(strings.TrimSpace(doc.Kind))
		if !isK8sWorkloadKind(kindLow) {
			continue
		}

		var podSpec k8sPodSpec
		switch kindLow {
		case "pod":
			podSpec = doc.Spec.k8sPodSpec
		case "cronjob":
			podSpec = doc.Spec.JobTemplate.Spec.Template.Spec
		default:
			podSpec = doc.Spec.Template.Spec
		}

		if podSpec.HostNetwork || podSpec.HostPID || podSpec.HostIPC {
			var flags []string
			if podSpec.HostNetwork {
				flags = append(flags, "hostNetwork")
			}
			if podSpec.HostPID {
				flags = append(flags, "hostPID")
			}
			if podSpec.HostIPC {
				flags = append(flags, "hostIPC")
			}
			findings = append(findings, schema.NewFinding(
				"PIPE-301", "iac", schema.SeverityCritical,
				"Kubernetes pod shares sensitive host namespaces",
				fmt.Sprintf("%s (doc #%d) enables host namespaces (%s).", doc.Kind, docIdx, strings.Join(flags, ", ")),
				target,
				map[string]any{"kind": doc.Kind, "host_flags": flags, "standard": "CIS Kubernetes 5.2"},
				"Disable hostNetwork, hostPID, and hostIPC unless required for dedicated node infrastructure agents.",
				"D3-NI", fmt.Sprintf("k8s-d%d-hostns", docIdx), now,
			))
		}

		podNonRoot := podSpec.SecurityContext != nil && podSpec.SecurityContext.RunAsNonRoot != nil && *podSpec.SecurityContext.RunAsNonRoot
		podRootUID := podSpec.SecurityContext != nil && podSpec.SecurityContext.RunAsUser != nil && *podSpec.SecurityContext.RunAsUser == 0

		allContainers := append([]k8sContainer{}, podSpec.InitContainers...)
		allContainers = append(allContainers, podSpec.Containers...)

		for cIdx, c := range allContainers {
			cName := c.Name
			if cName == "" {
				cName = fmt.Sprintf("container-%d", cIdx)
			}
			ctx := c.SecurityContext

			if ctx != nil && ctx.Privileged != nil && *ctx.Privileged {
				findings = append(findings, schema.NewFinding(
					"PIPE-301", "iac", schema.SeverityCritical,
					"Kubernetes container runs in privileged mode",
					fmt.Sprintf("Container %q in %s sets privileged: true.", cName, doc.Kind),
					target,
					map[string]any{"container": cName, "kind": doc.Kind, "standard": "CIS Kubernetes 5.2"},
					"Set privileged: false and grant only narrowly scoped Linux capabilities if necessary.",
					"D3-NI", fmt.Sprintf("k8s-d%d-%s-priv", docIdx, cName), now,
				))
			}

			nonRoot := podNonRoot
			if ctx != nil && ctx.RunAsNonRoot != nil {
				nonRoot = *ctx.RunAsNonRoot
			}
			rootUID := podRootUID || (ctx != nil && ctx.RunAsUser != nil && *ctx.RunAsUser == 0)
			if ctx != nil && ctx.RunAsUser != nil && *ctx.RunAsUser > 0 {
				rootUID = false
			}

			allowPrivEscDisabled := ctx != nil && ctx.AllowPrivilegeEscalation != nil && !*ctx.AllowPrivilegeEscalation
			dropsAllCaps := false
			if ctx != nil && ctx.Capabilities != nil {
				for _, d := range ctx.Capabilities.Drop {
					if strings.EqualFold(strings.TrimSpace(d), "ALL") {
						dropsAllCaps = true
						break
					}
				}
			}

			if !nonRoot || rootUID || !allowPrivEscDisabled || !dropsAllCaps {
				var missing []string
				if !nonRoot || rootUID {
					missing = append(missing, "runAsNonRoot: true")
				}
				if !allowPrivEscDisabled {
					missing = append(missing, "allowPrivilegeEscalation: false")
				}
				if !dropsAllCaps {
					missing = append(missing, "capabilities.drop: [ALL]")
				}
				findings = append(findings, schema.NewFinding(
					"PIPE-302", "iac", schema.SeverityHigh,
					"Kubernetes container lacks non-root or capability-drop hardening",
					fmt.Sprintf("Container %q in %s omits %s.", cName, doc.Kind, strings.Join(missing, ", ")),
					target,
					map[string]any{"container": cName, "missing_controls": missing, "standard": "CIS Kubernetes 5.2.6"},
					"Configure securityContext with runAsNonRoot: true, allowPrivilegeEscalation: false, and capabilities.drop: [ALL].",
					"D3-CH", fmt.Sprintf("k8s-d%d-%s-secctx", docIdx, cName), now,
				))
			}

			roRoot := ctx != nil && ctx.ReadOnlyRootFilesystem != nil && *ctx.ReadOnlyRootFilesystem
			hasLimits := c.Resources != nil && c.Resources.Limits["cpu"] != nil && c.Resources.Limits["memory"] != nil
			if !roRoot || !hasLimits {
				var missing []string
				if !roRoot {
					missing = append(missing, "readOnlyRootFilesystem: true")
				}
				if !hasLimits {
					missing = append(missing, "resources.limits.cpu/memory")
				}
				findings = append(findings, schema.NewFinding(
					"PIPE-303", "iac", schema.SeverityMedium,
					"Kubernetes container lacks readOnlyRootFilesystem or resource limits",
					fmt.Sprintf("Container %q in %s omits %s.", cName, doc.Kind, strings.Join(missing, ", ")),
					target,
					map[string]any{"container": cName, "missing_controls": missing, "standard": "CIS Kubernetes 5.2"},
					"Set readOnlyRootFilesystem: true (mount emptyDir for /tmp if needed) and enforce CPU/memory resource limits.",
					"D3-CH", fmt.Sprintf("k8s-d%d-%s-res", docIdx, cName), now,
				))
			}
		}
	}

	return findings
}
