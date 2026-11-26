package deps

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

const MaxDepsFileBytes = 4 * 1024 * 1024

type Component struct {
	Ecosystem    string `json:"ecosystem"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	PURL         string `json:"purl"`
	ManifestPath string `json:"manifest_path"`
	HashAlg      string `json:"hash_alg,omitempty"`
	HashValue    string `json:"hash_value,omitempty"`
	Line         int    `json:"line,omitempty"`
}

func InventoryFromPath(root string) ([]Component, []schema.Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, fmt.Errorf("stat deps path %q: %w", root, err)
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
				if isIgnoredDepsDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if isSupportedDepsFile(strings.ToLower(d.Name())) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("walk deps dir %q: %w", root, err)
		}
	}
	sort.Strings(files)

	var (
		comps    []Component
		findings []schema.Finding
		seenPURL = make(map[string]struct{})
		now      = time.Now().UTC()
	)

	addComp := func(c Component) {
		if c.Name == "" || c.Version == "" {
			return
		}
		if _, dup := seenPURL[c.PURL]; dup {
			return
		}
		seenPURL[c.PURL] = struct{}{}
		comps = append(comps, c)
	}

	for _, f := range files {
		base := strings.ToLower(filepath.Base(f))
		dir := filepath.Dir(f)
		target := "file://" + normalizeDepsPath(f)

		raw, readErr := readBoundedDepsFile(f)
		if readErr != nil {
			return nil, nil, readErr
		}

		switch base {
		case "go.mod":
			goSumHashes := loadGoSumHashes(filepath.Join(dir, "go.sum"))
			parsed := parseGoMod(raw, target, goSumHashes)
			for _, c := range parsed {
				addComp(c)
			}
			if len(parsed) > 0 && !fileExists(filepath.Join(dir, "go.sum")) {
				findings = append(findings, schema.NewFinding(
					"PIPE-104", "deps", schema.SeverityLow,
					"Missing go.sum integrity checksum file",
					"Module declares external dependencies in go.mod without a companion go.sum checksum file.",
					target,
					map[string]any{"ecosystem": "Go", "missing_file": "go.sum", "standard": "SLSA Build L2"},
					"Run 'go mod tidy' and commit go.sum to verify cryptographic module hashes in CI.",
					"D3-SBOM", fmt.Sprintf("%s-missing-gosum", sanitizeBase(f)), now,
				))
			}

		case "package.json":
			hasLock := fileExists(filepath.Join(dir, "package-lock.json")) ||
				fileExists(filepath.Join(dir, "yarn.lock")) ||
				fileExists(filepath.Join(dir, "pnpm-lock.yaml"))
			unpinned, hasAnyDeps := inspectPackageJSON(raw, target, now)
			findings = append(findings, unpinned...)
			if hasAnyDeps && !hasLock {
				findings = append(findings, schema.NewFinding(
					"PIPE-104", "deps", schema.SeverityLow,
					"Missing Node.js lockfile for declared dependencies",
					"package.json declares npm dependencies without package-lock.json, yarn.lock, or pnpm-lock.yaml.",
					target,
					map[string]any{"ecosystem": "npm", "standard": "SLSA Build L2"},
					"Generate and commit package-lock.json (via 'npm install --package-lock-only') and use 'npm ci' in CI.",
					"D3-SBOM", fmt.Sprintf("%s-missing-npmlock", sanitizeBase(f)), now,
				))
			}

		case "package-lock.json":
			parsed := parsePackageLockJSON(raw, target)
			for _, c := range parsed {
				addComp(c)
			}

		case "cargo.toml":
			hasLock := fileExists(filepath.Join(dir, "Cargo.lock"))
			unpinned, hasAnyDeps := inspectCargoToml(raw, target, now)
			findings = append(findings, unpinned...)
			if hasAnyDeps && !hasLock {
				findings = append(findings, schema.NewFinding(
					"PIPE-104", "deps", schema.SeverityLow,
					"Missing Cargo.lock for Rust dependencies",
					"Cargo.toml declares dependencies without a committed Cargo.lock lockfile.",
					target,
					map[string]any{"ecosystem": "crates.io", "standard": "SLSA Build L2"},
					"Run 'cargo generate-lockfile' and commit Cargo.lock for reproducible security builds.",
					"D3-SBOM", fmt.Sprintf("%s-missing-cargolock", sanitizeBase(f)), now,
				))
			}

		case "cargo.lock":
			for _, c := range parseCargoLock(raw, target) {
				addComp(c)
			}

		case "requirements.txt":
			parsed, reqFindings := parseRequirementsTxt(raw, target, now)
			for _, c := range parsed {
				addComp(c)
			}
			findings = append(findings, reqFindings...)
		}
	}

	sort.Slice(comps, func(i, j int) bool {
		if comps[i].Ecosystem != comps[j].Ecosystem {
			return comps[i].Ecosystem < comps[j].Ecosystem
		}
		if comps[i].Name != comps[j].Name {
			return comps[i].Name < comps[j].Name
		}
		return comps[i].Version < comps[j].Version
	})

	return comps, findings, nil
}

func parseGoMod(raw string, target string, sumHashes map[string]string) []Component {
	var comps []Component
	inRequire := false
	for idx, rawLine := range strings.Split(raw, "\n") {
		lineNo := idx + 1
		line := strings.TrimSpace(rawLine)
		if cm := strings.Index(line, "//"); cm >= 0 {
			line = strings.TrimSpace(line[:cm])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "require (") || line == "require(" {
			inRequire = true
			continue
		}
		if inRequire {
			if line == ")" {
				inRequire = false
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				mod, ver := fields[0], fields[1]
				comps = append(comps, makeGoComponent(mod, ver, target, lineNo, sumHashes))
			}
			continue
		}
		if strings.HasPrefix(line, "require ") {
			fields := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(fields) >= 2 && fields[0] != "(" {
				comps = append(comps, makeGoComponent(fields[0], fields[1], target, lineNo, sumHashes))
			}
		}
	}
	return comps
}

func makeGoComponent(mod, ver, target string, lineNo int, sumHashes map[string]string) Component {
	c := Component{
		Ecosystem:    "Go",
		Name:         mod,
		Version:      ver,
		PURL:         fmt.Sprintf("pkg:golang/%s@%s", mod, ver),
		ManifestPath: target,
		Line:         lineNo,
	}
	if h, ok := sumHashes[mod+"@"+ver]; ok {
		c.HashAlg = "SHA-256"
		c.HashValue = h
	}
	return c
}

func loadGoSumHashes(path string) map[string]string {
	out := make(map[string]string)
	raw, err := readBoundedDepsFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 3 && !strings.HasSuffix(fields[1], "/go.mod") {
			if strings.HasPrefix(fields[2], "h1:") {
				out[fields[0]+"@"+fields[1]] = fields[2]
			}
		}
	}
	return out
}

func inspectPackageJSON(raw string, target string, now time.Time) ([]schema.Finding, bool) {
	var doc struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, false
	}

	var findings []schema.Finding
	totalDeps := len(doc.Dependencies) + len(doc.DevDependencies)
	checkMap := func(m map[string]string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, pkg := range keys {
			ver := strings.TrimSpace(m[pkg])
			low := strings.ToLower(ver)
			if low == "*" || low == "latest" || strings.HasPrefix(low, "git+") ||
				strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "github:") {
				findings = append(findings, schema.NewFinding(
					"PIPE-103", "deps", schema.SeverityMedium,
					"Unpinned mutable npm dependency version",
					fmt.Sprintf("Package %q in package.json uses unpinned spec %q.", pkg, ver),
					target,
					map[string]any{"ecosystem": "npm", "package": pkg, "version_spec": ver, "standard": "SLSA Build L2"},
					fmt.Sprintf("Pin %q to an explicit semver version and commit package-lock.json.", pkg),
					"D3-SBOM", fmt.Sprintf("npm-unpinned-%s", pkg), now,
				))
			}
		}
	}
	checkMap(doc.Dependencies)
	checkMap(doc.DevDependencies)
	return findings, totalDeps > 0
}

func parsePackageLockJSON(raw string, target string) []Component {
	var doc struct {
		Packages map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil
	}

	var comps []Component
	for key, meta := range doc.Packages {
		if key == "" || meta.Version == "" {
			continue
		}
		idx := strings.LastIndex(key, "node_modules/")
		if idx < 0 {
			continue
		}
		name := key[idx+len("node_modules/"):]
		if name == "" {
			continue
		}
		comps = append(comps, makeNpmComponent(name, meta.Version, meta.Integrity, target))
	}

	if len(comps) == 0 {
		for name, meta := range doc.Dependencies {
			if name == "" || meta.Version == "" {
				continue
			}
			comps = append(comps, makeNpmComponent(name, meta.Version, meta.Integrity, target))
		}
	}
	return comps
}

func makeNpmComponent(name, ver, integrity, target string) Component {
	purlName := strings.ReplaceAll(name, "@", "%40")
	c := Component{
		Ecosystem:    "npm",
		Name:         name,
		Version:      ver,
		PURL:         fmt.Sprintf("pkg:npm/%s@%s", purlName, ver),
		ManifestPath: target,
	}
	if strings.HasPrefix(integrity, "sha512-") {
		c.HashAlg = "SHA-512"
		c.HashValue = strings.TrimPrefix(integrity, "sha512-")
	}
	return c
}

func inspectCargoToml(raw string, target string, now time.Time) ([]schema.Finding, bool) {
	var findings []schema.Finding
	inDeps := false
	hasAny := false

	for idx, rawLine := range strings.Split(raw, "\n") {
		lineNo := idx + 1
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			low := strings.ToLower(line)
			inDeps = low == "[dependencies]" || low == "[dev-dependencies]" || low == "[build-dependencies]"
			continue
		}
		if !inDeps {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		hasAny = true
		pkg := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if strings.Contains(val, `"*"`) || strings.Contains(val, "git =") || strings.Contains(val, "git=") {
			findings = append(findings, schema.NewFinding(
				"PIPE-103", "deps", schema.SeverityMedium,
				"Unpinned wildcard or Git dependency in Cargo.toml",
				fmt.Sprintf("Crate %q on line %d declares wildcard '*' or mutable git dependency.", pkg, lineNo),
				target,
				map[string]any{"line": lineNo, "ecosystem": "crates.io", "package": pkg, "standard": "SLSA Build L2"},
				fmt.Sprintf("Pin %q to a vetted crates.io semver requirement.", pkg),
				"D3-SBOM", fmt.Sprintf("cargo-unpinned-%s-l%d", pkg, lineNo), now,
			))
		}
	}
	return findings, hasAny
}

func parseCargoLock(raw string, target string) []Component {
	var comps []Component
	var curName, curVer, curSum string
	inPkg := false

	flush := func() {
		if inPkg && curName != "" && curVer != "" {
			c := Component{
				Ecosystem:    "crates.io",
				Name:         curName,
				Version:      curVer,
				PURL:         fmt.Sprintf("pkg:cargo/%s@%s", curName, curVer),
				ManifestPath: target,
			}
			if curSum != "" {
				c.HashAlg = "SHA-256"
				c.HashValue = curSum
			}
			comps = append(comps, c)
		}
		curName, curVer, curSum = "", "", ""
	}

	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "[[package]]" {
			flush()
			inPkg = true
			continue
		}
		if !inPkg || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			curName = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		} else if strings.HasPrefix(line, "version = ") {
			curVer = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		} else if strings.HasPrefix(line, "checksum = ") {
			curSum = strings.Trim(strings.TrimPrefix(line, "checksum = "), `"`)
		}
	}
	flush()
	return comps
}

func parseRequirementsTxt(raw string, target string, now time.Time) ([]Component, []schema.Finding) {
	var (
		comps    []Component
		findings []schema.Finding
	)
	for idx, rawLine := range strings.Split(raw, "\n") {
		lineNo := idx + 1
		line := strings.TrimSpace(rawLine)
		if hashIdx := strings.IndexByte(line, '#'); hashIdx >= 0 {
			line = strings.TrimSpace(line[:hashIdx])
		}
		if line == "" || strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--") {
			continue
		}

		low := strings.ToLower(line)
		if strings.Contains(low, "git+") || strings.Contains(low, "http://") || strings.Contains(low, "https://") {
			findings = append(findings, schema.NewFinding(
				"PIPE-103", "deps", schema.SeverityMedium,
				"Unpinned VCS or remote URL dependency in requirements.txt",
				fmt.Sprintf("Line %d references mutable remote URL %q.", lineNo, line),
				target,
				map[string]any{"line": lineNo, "ecosystem": "PyPI", "spec": line, "standard": "SLSA Build L2"},
				"Replace remote/VCS URLs with pinned PyPI versions (pkg==x.y.z) and --require-hashes.",
				"D3-SBOM", fmt.Sprintf("pypi-vcs-l%d", lineNo), now,
			))
			continue
		}

		// Strip environment markers (; python_version < ...) before checking exact == pin.
		spec := line
		if semi := strings.IndexByte(spec, ';'); semi >= 0 {
			spec = strings.TrimSpace(spec[:semi])
		}
		if eqIdx := strings.Index(spec, "=="); eqIdx > 0 {
			name := strings.TrimSpace(spec[:eqIdx])
			rest := strings.TrimSpace(spec[eqIdx+2:])
			ver := strings.Fields(rest)[0]
			if br := strings.IndexByte(name, '['); br >= 0 {
				name = name[:br]
			}
			if name != "" && ver != "" && !strings.Contains(ver, "*") {
				normName := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
				comps = append(comps, Component{
					Ecosystem:    "PyPI",
					Name:         normName,
					Version:      ver,
					PURL:         fmt.Sprintf("pkg:pypi/%s@%s", normName, ver),
					ManifestPath: target,
					Line:         lineNo,
				})
				continue
			}
		}

		findings = append(findings, schema.NewFinding(
			"PIPE-103", "deps", schema.SeverityMedium,
			"Unpinned Python dependency in requirements.txt",
			fmt.Sprintf("Requirement %q on line %d lacks an exact == version pin.", spec, lineNo),
			target,
			map[string]any{"line": lineNo, "ecosystem": "PyPI", "spec": spec, "standard": "SLSA Build L2"},
			"Pin exact dependency versions using 'package==x.y.z' (or Poetry/uv lockfiles).",
			"D3-SBOM", fmt.Sprintf("pypi-unpinned-l%d", lineNo), now,
		))
	}
	return comps, findings
}

func readBoundedDepsFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > MaxDepsFileBytes {
		return "", fmt.Errorf("file %q exceeds %d byte limit", path, MaxDepsFileBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxDepsFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(raw) > MaxDepsFileBytes {
		return "", fmt.Errorf("file %q exceeds %d byte limit", path, MaxDepsFileBytes)
	}
	return string(raw), nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isIgnoredDepsDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == "target" || name == "dist" || name == "vendor"
}

func isSupportedDepsFile(lowerBase string) bool {
	switch lowerBase {
	case "go.mod", "package.json", "package-lock.json", "cargo.toml", "cargo.lock", "requirements.txt":
		return true
	default:
		return false
	}
}

func normalizeDepsPath(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

func sanitizeBase(p string) string {
	return schema.SanitizeIDPart(filepath.Base(p))
}
