package iac

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

const MaxIaCFileBytes = 2 * 1024 * 1024

func ScanPath(root string) ([]schema.Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat IaC path %q: %w", root, err)
	}

	var files []string
	if !info.IsDir() {
		files = append(files, root)
	} else {
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if isIgnoredIaCDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if isCandidateIaCFile(d.Name()) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk IaC dir %q: %w", root, err)
		}
	}
	sort.Strings(files)

	var findings []schema.Finding
	for _, f := range files {
		raw, err := readBoundedIaC(f)
		if err != nil {
			return nil, err
		}
		target := "file://" + strings.ReplaceAll(f, `\`, "/")
		findings = append(findings, ScanFileContent(f, raw, target)...)
	}
	return findings, nil
}

func ScanContent(content, kind, target string) ([]schema.Finding, error) {
	if len(content) > MaxIaCFileBytes {
		return nil, fmt.Errorf("IaC content exceeds %d byte limit", MaxIaCFileBytes)
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "dockerfile", "docker":
		return LintDockerfile(content, target), nil
	case "kubernetes", "k8s":
		return LintKubernetesYAML(content, target), nil
	case "terraform", "tf":
		return LintTerraform(content, target), nil
	default:
		return nil, fmt.Errorf("unsupported IaC kind %q: expected dockerfile, kubernetes, or terraform", kind)
	}
}

func ScanFileContent(path, content, target string) []schema.Finding {
	low := strings.ToLower(filepath.Base(path))
	switch {
	case isDockerfileName(low):
		return LintDockerfile(content, target)
	case strings.HasSuffix(low, ".tf"):
		return LintTerraform(content, target)
	case (strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml")) && LooksLikeKubernetesYAML(content):
		return LintKubernetesYAML(content, target)
	default:
		return nil
	}
}

func isIgnoredIaCDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == "target" || name == "dist" || name == "vendor"
}

func isDockerfileName(lowerBase string) bool {
	return lowerBase == "dockerfile" ||
		strings.HasPrefix(lowerBase, "dockerfile.") ||
		strings.HasSuffix(lowerBase, ".dockerfile")
}

func isCandidateIaCFile(name string) bool {
	low := strings.ToLower(name)
	return isDockerfileName(low) ||
		strings.HasSuffix(low, ".tf") ||
		strings.HasSuffix(low, ".yml") ||
		strings.HasSuffix(low, ".yaml")
}

func readBoundedIaC(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open IaC file %q: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat IaC file %q: %w", path, err)
	}
	if info.Size() > MaxIaCFileBytes {
		return "", fmt.Errorf("IaC file %q exceeds %d byte limit", path, MaxIaCFileBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxIaCFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("read IaC file %q: %w", path, err)
	}
	if len(raw) > MaxIaCFileBytes {
		return "", fmt.Errorf("IaC file %q exceeds %d byte limit", path, MaxIaCFileBytes)
	}
	return string(raw), nil
}
