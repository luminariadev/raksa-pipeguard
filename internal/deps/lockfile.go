package deps

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
	"gopkg.in/yaml.v3"
)

const MaxDepsFileBytes = 4 * 1024 * 1024

// DefaultDeniedLicenses lists restrictive copyleft/source-available license prefixes flagged by PIPE-105.
var DefaultDeniedLicenses = []string{"AGPL", "GPL", "SSPL", "BUSL"}

type Component struct {
	Ecosystem    string `json:"ecosystem"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	PURL         string `json:"purl"`
	ManifestPath string `json:"manifest_path"`
	HashAlg      string `json:"hash_alg,omitempty"`
	HashValue    string `json:"hash_value,omitempty"`
	License      string `json:"license,omitempty"`
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

		case "yarn.lock":
			for _, c := range parseYarnLock(raw, target) {
				addComp(c)
			}

		case "pnpm-lock.yaml":
			for _, c := range parsePnpmLockYAML(raw, target) {
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

		case "pyproject.toml":
			hasPyLock := fileExists(filepath.Join(dir, "poetry.lock")) || fileExists(filepath.Join(dir, "uv.lock"))
			if pyprojectDeclaresDeps(raw) && !hasPyLock {
				findings = append(findings, schema.NewFinding(
					"PIPE-104", "deps", schema.SeverityLow,
					"Missing Python lockfile (poetry.lock or uv.lock) for pyproject.toml",
					"pyproject.toml declares Python dependencies without a companion poetry.lock or uv.lock lockfile.",
					target,
					map[string]any{"ecosystem": "PyPI", "standard": "SLSA Build L2"},
					"Generate and commit poetry.lock or uv.lock for reproducible dependency resolution.",
					"D3-SBOM", fmt.Sprintf("%s-missing-pylock", sanitizeBase(f)), now,
				))
			}

		case "poetry.lock", "uv.lock":
			for _, c := range parsePythonLock(raw, target) {
				addComp(c)
			}

		case "composer.json":
			hasLock := fileExists(filepath.Join(dir, "composer.lock"))
			if composerDeclaresDeps(raw) && !hasLock {
				findings = append(findings, schema.NewFinding(
					"PIPE-104", "deps", schema.SeverityLow,
					"Missing composer.lock for PHP dependencies",
					"composer.json declares Packagist dependencies without a committed composer.lock file.",
					target,
					map[string]any{"ecosystem": "Packagist", "standard": "SLSA Build L2"},
					"Run 'composer update --lock' or 'composer install' and commit composer.lock.",
					"D3-SBOM", fmt.Sprintf("%s-missing-composerlock", sanitizeBase(f)), now,
				))
			}

		case "composer.lock":
			for _, c := range parseComposerLock(raw, target) {
				addComp(c)
			}

		case "pom.xml":
			parsed, pomFindings := parsePomXML(raw, target, now)
			for _, c := range parsed {
				addComp(c)
			}
			findings = append(findings, pomFindings...)
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
			License   string `json:"license"`
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
		c := makeNpmComponent(name, meta.Version, meta.Integrity, target)
		c.License = strings.TrimSpace(meta.License)
		comps = append(comps, c)
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

func parseTOMLPackageBlocks(raw string, emit func(name, ver, checksum string, isLocal bool)) {
	var curName, curVer, curSum string
	var isLocal bool
	inPkg := false

	flush := func() {
		if inPkg && curName != "" && curVer != "" {
			emit(curName, curVer, curSum, isLocal)
		}
		curName, curVer, curSum = "", "", ""
		isLocal = false
	}

	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "[[package]]" {
			flush()
			inPkg = true
			continue
		}
		if strings.HasPrefix(line, "[") && line != "[[package]]" {
			flush()
			inPkg = false
			continue
		}
		if !inPkg || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "name = "):
			curName = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		case strings.HasPrefix(line, "version = "):
			curVer = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		case strings.HasPrefix(line, "checksum = "):
			curSum = strings.Trim(strings.TrimPrefix(line, "checksum = "), `"`)
		case strings.HasPrefix(line, "source = ") && (strings.Contains(line, `virtual = "."`) || strings.Contains(line, `editable = "."`)):
			isLocal = true
		}
	}
	flush()
}

func parseCargoLock(raw string, target string) []Component {
	var comps []Component
	parseTOMLPackageBlocks(raw, func(name, ver, checksum string, _ bool) {
		c := Component{
			Ecosystem:    "crates.io",
			Name:         name,
			Version:      ver,
			PURL:         fmt.Sprintf("pkg:cargo/%s@%s", name, ver),
			ManifestPath: target,
		}
		if checksum != "" {
			c.HashAlg = "SHA-256"
			c.HashValue = checksum
		}
		comps = append(comps, c)
	})
	return comps
}

func parsePythonLock(raw string, target string) []Component {
	var comps []Component
	parseTOMLPackageBlocks(raw, func(name, ver, _ string, isLocal bool) {
		if isLocal {
			return
		}
		normName := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		comps = append(comps, Component{
			Ecosystem:    "PyPI",
			Name:         normName,
			Version:      ver,
			PURL:         fmt.Sprintf("pkg:pypi/%s@%s", normName, ver),
			ManifestPath: target,
		})
	})
	return comps
}

func parseYarnLock(raw string, target string) []Component {
	var comps []Component
	var curName, curVer, curIntegrity string
	inEntry := false

	flush := func() {
		if inEntry && curName != "" && curVer != "" {
			comps = append(comps, makeNpmComponent(curName, curVer, curIntegrity, target))
		}
		curName, curVer, curIntegrity = "", "", ""
		inEntry = false
	}

	for _, rawLine := range strings.Split(raw, "\n") {
		trimmedRight := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(trimmedRight)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Top-level stanza header ends with ':' and has no leading indentation.
		if trimmedRight[0] != ' ' && trimmedRight[0] != '\t' && strings.HasSuffix(trimmed, ":") {
			flush()
			header := strings.TrimSuffix(trimmed, ":")
			if header == "__metadata" {
				continue
			}
			firstSpec := strings.TrimSpace(strings.SplitN(header, ",", 2)[0])
			firstSpec = strings.Trim(firstSpec, `"'`)
			if at := strings.LastIndex(firstSpec, "@"); at > 0 {
				curName = firstSpec[:at]
				inEntry = true
			}
			continue
		}
		if !inEntry {
			continue
		}
		if strings.HasPrefix(trimmed, "version ") {
			curVer = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "version ")), `"'`)
		} else if strings.HasPrefix(trimmed, "version:") {
			curVer = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "version:")), `"'`)
		} else if strings.HasPrefix(trimmed, "integrity ") {
			curIntegrity = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "integrity ")), `"'`)
		}
	}
	flush()
	return comps
}

func parsePnpmLockYAML(raw string, target string) []Component {
	var doc struct {
		Packages map[string]struct {
			Resolution struct {
				Integrity string `yaml:"integrity"`
			} `yaml:"resolution"`
		} `yaml:"packages"`
		Snapshots map[string]struct{} `yaml:"snapshots"`
	}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return nil
	}

	var comps []Component
	parseKey := func(pkgKey, integrity string) {
		k := strings.TrimPrefix(strings.TrimSpace(pkgKey), "/")
		if paren := strings.IndexByte(k, '('); paren > 0 {
			k = k[:paren]
		}
		var name, ver string
		if at := strings.LastIndex(k, "@"); at > 0 {
			name = k[:at]
			ver = k[at+1:]
		} else if slash := strings.LastIndex(k, "/"); slash > 0 {
			name = k[:slash]
			ver = k[slash+1:]
		}
		if name != "" && ver != "" {
			comps = append(comps, makeNpmComponent(name, ver, integrity, target))
		}
	}

	keys := make([]string, 0, len(doc.Packages))
	for k := range doc.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parseKey(k, doc.Packages[k].Resolution.Integrity)
	}
	if len(comps) == 0 && len(doc.Snapshots) > 0 {
		skeys := make([]string, 0, len(doc.Snapshots))
		for k := range doc.Snapshots {
			skeys = append(skeys, k)
		}
		sort.Strings(skeys)
		for _, k := range skeys {
			parseKey(k, "")
		}
	}
	return comps
}

func pyprojectDeclaresDeps(raw string) bool {
	inPoetry := false
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inPoetry = strings.EqualFold(line, "[tool.poetry.dependencies]")
			continue
		}
		if strings.HasPrefix(line, "dependencies = [") || strings.HasPrefix(line, "dependencies=[") {
			return !strings.Contains(line, "[]")
		}
		if inPoetry {
			if eq := strings.IndexByte(line, '='); eq > 0 {
				pkg := strings.TrimSpace(line[:eq])
				if !strings.EqualFold(pkg, "python") {
					return true
				}
			}
		}
	}
	return false
}

func composerDeclaresDeps(raw string) bool {
	var doc struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return false
	}
	for k := range doc.Require {
		low := strings.ToLower(k)
		if low != "php" && !strings.HasPrefix(low, "ext-") && !strings.HasPrefix(low, "lib-") {
			return true
		}
	}
	return len(doc.RequireDev) > 0
}

func parseComposerLock(raw string, target string) []Component {
	var doc struct {
		Packages []struct {
			Name    string   `json:"name"`
			Version string   `json:"version"`
			License []string `json:"license"`
			Dist    struct {
				Shasum string `json:"shasum"`
			} `json:"dist"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string   `json:"name"`
			Version string   `json:"version"`
			License []string `json:"license"`
			Dist    struct {
				Shasum string `json:"shasum"`
			} `json:"dist"`
		} `json:"packages-dev"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil
	}

	var comps []Component
	add := func(name, ver string, licenses []string, shasum string) {
		if name == "" || ver == "" {
			return
		}
		c := Component{
			Ecosystem:    "Packagist",
			Name:         name,
			Version:      strings.TrimPrefix(ver, "v"),
			PURL:         fmt.Sprintf("pkg:composer/%s@%s", name, strings.TrimPrefix(ver, "v")),
			ManifestPath: target,
			License:      strings.Join(licenses, " OR "),
		}
		if shasum != "" {
			c.HashAlg = "SHA-1"
			c.HashValue = shasum
		}
		comps = append(comps, c)
	}
	for _, p := range doc.Packages {
		add(p.Name, p.Version, p.License, p.Dist.Shasum)
	}
	for _, p := range doc.PackagesDev {
		add(p.Name, p.Version, p.License, p.Dist.Shasum)
	}
	return comps
}

func parsePomXML(raw string, target string, now time.Time) ([]Component, []schema.Finding) {
	type xmlProp struct {
		XMLName xml.Name
		Value   string `xml:",chardata"`
	}
	type xmlDep struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	}
	var proj struct {
		Properties struct {
			Entries []xmlProp `xml:",any"`
		} `xml:"properties"`
		Dependencies struct {
			List []xmlDep `xml:"dependency"`
		} `xml:"dependencies"`
		DependencyManagement struct {
			Dependencies struct {
				List []xmlDep `xml:"dependency"`
			} `xml:"dependencies"`
		} `xml:"dependencyManagement"`
	}
	if err := xml.Unmarshal([]byte(raw), &proj); err != nil {
		return nil, nil
	}

	props := make(map[string]string, len(proj.Properties.Entries))
	for _, p := range proj.Properties.Entries {
		props[p.XMLName.Local] = strings.TrimSpace(p.Value)
	}
	resolveProp := func(v string) string {
		s := strings.TrimSpace(v)
		if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
			if val, ok := props[s[2:len(s)-1]]; ok && val != "" {
				return val
			}
		}
		return s
	}

	allDeps := append([]xmlDep{}, proj.Dependencies.List...)
	allDeps = append(allDeps, proj.DependencyManagement.Dependencies.List...)

	var (
		comps    []Component
		findings []schema.Finding
	)
	for _, d := range allDeps {
		g := strings.TrimSpace(d.GroupID)
		a := strings.TrimSpace(d.ArtifactID)
		v := resolveProp(d.Version)
		if g == "" || a == "" || v == "" {
			continue
		}
		up := strings.ToUpper(v)
		if up == "LATEST" || up == "RELEASE" || strings.Contains(v, ",") || strings.Contains(v, "SNAPSHOT") {
			findings = append(findings, schema.NewFinding(
				"PIPE-103", "deps", schema.SeverityMedium,
				"Unpinned Maven dependency version in pom.xml",
				fmt.Sprintf("Maven artifact %s:%s uses mutable version spec %q.", g, a, v),
				target,
				map[string]any{"ecosystem": "Maven", "package": g + ":" + a, "version_spec": v, "standard": "SLSA Build L2"},
				"Pin Maven dependency versions cleanly or manage releases through an immutable BOM.",
				"D3-SBOM", fmt.Sprintf("maven-unpinned-%s-%s", g, a), now,
			))
			continue
		}
		if strings.HasPrefix(v, "${") {
			continue
		}
		coord := g + ":" + a
		comps = append(comps, Component{
			Ecosystem:    "Maven",
			Name:         coord,
			Version:      v,
			PURL:         fmt.Sprintf("pkg:maven/%s/%s@%s", g, a, v),
			ManifestPath: target,
		})
	}
	return comps, findings
}

// AuditLicenses inspects component SPDX license metadata against prohibited license family prefixes.
func AuditLicenses(comps []Component, denied []string) []schema.Finding {
	rules := denied
	if len(rules) == 0 {
		rules = DefaultDeniedLicenses
	}
	normDenied := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		tok := licenseFamilyToken(r)
		if tok != "" {
			normDenied[tok] = struct{}{}
		}
	}

	var findings []schema.Finding
	now := time.Now().UTC()
	for _, c := range comps {
		if strings.TrimSpace(c.License) == "" {
			continue
		}
		matched := ""
		for _, part := range splitLicenseTokens(c.License) {
			fam := licenseFamilyToken(part)
			if _, banned := normDenied[fam]; banned {
				matched = part
				break
			}
		}
		if matched == "" {
			continue
		}
		findings = append(findings, schema.NewFinding(
			"PIPE-105", "deps", schema.SeverityMedium,
			fmt.Sprintf("Restricted license %q on dependency %s@%s", c.License, c.Name, c.Version),
			fmt.Sprintf("Component %s (%s %s) declares license %q matching restricted policy family.", c.Name, c.Ecosystem, c.Version, c.License),
			c.ManifestPath,
			map[string]any{
				"ecosystem": c.Ecosystem,
				"package":   c.Name,
				"version":   c.Version,
				"license":   c.License,
				"matched":   matched,
				"standard":  "SPDX License Compliance",
			},
			"Review legal obligations for copyleft/restricted licenses or substitute a permissive dependency.",
			"D3-SBOM",
			fmt.Sprintf("lic-%s-%s-%s", c.Name, c.Version, matched),
			now,
		))
	}
	return findings
}

func splitLicenseTokens(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '/' || r == '(' || r == ')' || r == '\t'
	})
}

func licenseFamilyToken(token string) string {
	low := strings.ToLower(strings.TrimSpace(token))
	if low == "" || low == "or" || low == "and" || low == "with" {
		return ""
	}
	var prefix strings.Builder
	for _, r := range low {
		if unicode.IsLetter(r) {
			prefix.WriteRune(r)
		} else {
			break
		}
	}
	fam := strings.TrimSuffix(prefix.String(), "v")
	return fam
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
	case "go.mod", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"cargo.toml", "cargo.lock", "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock",
		"composer.json", "composer.lock", "pom.xml":
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
