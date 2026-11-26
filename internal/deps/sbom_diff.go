package deps

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const MaxSBOMFileBytes = 16 * 1024 * 1024

type SBOMChange struct {
	Ecosystem  string `json:"ecosystem"`
	Name       string `json:"name"`
	OldVersion string `json:"old_version,omitempty"`
	NewVersion string `json:"new_version,omitempty"`
	OldLicense string `json:"old_license,omitempty"`
	NewLicense string `json:"new_license,omitempty"`
}

type SBOMDiff struct {
	OldCount       int          `json:"old_count"`
	NewCount       int          `json:"new_count"`
	Added          []SBOMChange `json:"added"`
	Removed        []SBOMChange `json:"removed"`
	VersionChanged []SBOMChange `json:"version_changed"`
	LicenseChanged []SBOMChange `json:"license_changed"`
}

// HasChanges returns true if any component was added, removed, upgraded/downgraded, or changed license.
func (d SBOMDiff) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.VersionChanged) > 0 || len(d.LicenseChanged) > 0
}

// DiffSBOMFiles parses two CycloneDX 1.5 or SPDX 2.3 JSON SBOM files and computes component differences.
func DiffSBOMFiles(oldPath, newPath string) (SBOMDiff, error) {
	oldComps, err := LoadSBOMComponents(oldPath)
	if err != nil {
		return SBOMDiff{}, fmt.Errorf("load old SBOM: %w", err)
	}
	newComps, err := LoadSBOMComponents(newPath)
	if err != nil {
		return SBOMDiff{}, fmt.Errorf("load new SBOM: %w", err)
	}
	return DiffSBOM(oldComps, newComps), nil
}

// LoadSBOMComponents decodes CycloneDX 1.5 or SPDX 2.3 JSON files into normalized Component slices.
func LoadSBOMComponents(path string) ([]Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open SBOM %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat SBOM %q: %w", path, err)
	}
	if info.Size() > MaxSBOMFileBytes {
		return nil, fmt.Errorf("SBOM %q exceeds %d byte limit", path, MaxSBOMFileBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxSBOMFileBytes+1))
	if err != nil || len(raw) > MaxSBOMFileBytes {
		return nil, fmt.Errorf("read SBOM %q failed or too large", path)
	}

	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("parse SBOM JSON %q: %w", path, err)
	}

	if strings.EqualFold(probe.BOMFormat, "CycloneDX") {
		var cdx struct {
			Components []struct {
				Name     string `json:"name"`
				Version  string `json:"version"`
				PURL     string `json:"purl"`
				Licenses []struct {
					License *struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"license"`
				} `json:"licenses"`
			} `json:"components"`
		}
		if err := json.Unmarshal(raw, &cdx); err != nil {
			return nil, fmt.Errorf("decode CycloneDX components: %w", err)
		}
		out := make([]Component, 0, len(cdx.Components))
		for _, c := range cdx.Components {
			lic := ""
			if len(c.Licenses) > 0 && c.Licenses[0].License != nil {
				lic = strings.TrimSpace(c.Licenses[0].License.ID)
				if lic == "" {
					lic = strings.TrimSpace(c.Licenses[0].License.Name)
				}
			}
			out = append(out, Component{
				Ecosystem: ecosystemFromPURL(c.PURL),
				Name:      c.Name,
				Version:   c.Version,
				PURL:      c.PURL,
				License:   lic,
			})
		}
		return out, nil
	}

	if strings.TrimSpace(probe.SPDXVersion) != "" {
		var spdx struct {
			Packages []struct {
				Name            string            `json:"name"`
				VersionInfo     string            `json:"versionInfo"`
				LicenseDeclared string            `json:"licenseDeclared"`
				ExternalRefs    []spdxExternalRef `json:"externalRefs"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(raw, &spdx); err != nil {
			return nil, fmt.Errorf("decode SPDX packages: %w", err)
		}
		out := make([]Component, 0, len(spdx.Packages))
		for _, p := range spdx.Packages {
			purl := ""
			for _, ref := range p.ExternalRefs {
				if strings.EqualFold(ref.ReferenceType, "purl") {
					purl = ref.ReferenceLocator
					break
				}
			}
			lic := strings.TrimSpace(p.LicenseDeclared)
			if strings.EqualFold(lic, "NOASSERTION") {
				lic = ""
			}
			out = append(out, Component{
				Ecosystem: ecosystemFromPURL(purl),
				Name:      p.Name,
				Version:   p.VersionInfo,
				PURL:      purl,
				License:   lic,
			})
		}
		return out, nil
	}

	return nil, fmt.Errorf("unsupported SBOM format in %q (expected CycloneDX or SPDX 2.3 JSON)", path)
}

func ecosystemFromPURL(purl string) string {
	low := strings.ToLower(strings.TrimSpace(purl))
	if !strings.HasPrefix(low, "pkg:") {
		return "unknown"
	}
	rest := strings.TrimPrefix(low, "pkg:")
	if slash := strings.IndexByte(rest, '/'); slash > 0 {
		rest = rest[:slash]
	}
	switch rest {
	case "golang":
		return "Go"
	case "pypi":
		return "PyPI"
	case "cargo":
		return "crates.io"
	case "composer":
		return "Packagist"
	case "maven":
		return "Maven"
	case "apk":
		return "Alpine"
	case "deb":
		return "Debian"
	default:
		return rest
	}
}

// DiffSBOM computes deterministic component additions, removals, version changes, and license changes.
func DiffSBOM(oldComps, newComps []Component) SBOMDiff {
	index := func(list []Component) map[string]Component {
		m := make(map[string]Component, len(list))
		for _, c := range list {
			key := strings.ToLower(c.Ecosystem) + "|" + strings.ToLower(c.Name)
			m[key] = c
		}
		return m
	}

	oldMap := index(oldComps)
	newMap := index(newComps)

	diff := SBOMDiff{
		OldCount:       len(oldComps),
		NewCount:       len(newComps),
		Added:          []SBOMChange{},
		Removed:        []SBOMChange{},
		VersionChanged: []SBOMChange{},
		LicenseChanged: []SBOMChange{},
	}

	for key, nc := range newMap {
		oc, ok := oldMap[key]
		if !ok {
			diff.Added = append(diff.Added, SBOMChange{
				Ecosystem:  nc.Ecosystem,
				Name:       nc.Name,
				NewVersion: nc.Version,
				NewLicense: nc.License,
			})
			continue
		}
		if oc.Version != nc.Version {
			diff.VersionChanged = append(diff.VersionChanged, SBOMChange{
				Ecosystem:  nc.Ecosystem,
				Name:       nc.Name,
				OldVersion: oc.Version,
				NewVersion: nc.Version,
			})
		}
		if !strings.EqualFold(strings.TrimSpace(oc.License), strings.TrimSpace(nc.License)) &&
			(strings.TrimSpace(oc.License) != "" || strings.TrimSpace(nc.License) != "") {
			diff.LicenseChanged = append(diff.LicenseChanged, SBOMChange{
				Ecosystem:  nc.Ecosystem,
				Name:       nc.Name,
				OldVersion: oc.Version,
				NewVersion: nc.Version,
				OldLicense: oc.License,
				NewLicense: nc.License,
			})
		}
	}

	for key, oc := range oldMap {
		if _, ok := newMap[key]; !ok {
			diff.Removed = append(diff.Removed, SBOMChange{
				Ecosystem:  oc.Ecosystem,
				Name:       oc.Name,
				OldVersion: oc.Version,
				OldLicense: oc.License,
			})
		}
	}

	sortChanges := func(s []SBOMChange) {
		sort.Slice(s, func(i, j int) bool {
			if s[i].Ecosystem != s[j].Ecosystem {
				return s[i].Ecosystem < s[j].Ecosystem
			}
			return s[i].Name < s[j].Name
		})
	}
	sortChanges(diff.Added)
	sortChanges(diff.Removed)
	sortChanges(diff.VersionChanged)
	sortChanges(diff.LicenseChanged)

	return diff
}

// FormatSBOMDiff renders an SBOMDiff in table, json, or markdown formats.
func FormatSBOMDiff(diff SBOMDiff, format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "table":
		var b strings.Builder
		fmt.Fprintf(&b, "SBOM Diff | old: %d -> new: %d | added: %d | removed: %d | version_changed: %d | license_changed: %d\n",
			diff.OldCount, diff.NewCount, len(diff.Added), len(diff.Removed), len(diff.VersionChanged), len(diff.LicenseChanged))
		for _, c := range diff.Added {
			fmt.Fprintf(&b, "+ ADDED    %-10s %s @ %s (%s)\n", c.Ecosystem, c.Name, c.NewVersion, emptyDash(c.NewLicense))
		}
		for _, c := range diff.Removed {
			fmt.Fprintf(&b, "- REMOVED  %-10s %s @ %s\n", c.Ecosystem, c.Name, c.OldVersion)
		}
		for _, c := range diff.VersionChanged {
			fmt.Fprintf(&b, "~ VERSION  %-10s %s: %s -> %s\n", c.Ecosystem, c.Name, c.OldVersion, c.NewVersion)
		}
		for _, c := range diff.LicenseChanged {
			fmt.Fprintf(&b, "! LICENSE  %-10s %s: %s -> %s\n", c.Ecosystem, c.Name, emptyDash(c.OldLicense), emptyDash(c.NewLicense))
		}
		return b.String(), nil

	case "json":
		raw, err := json.MarshalIndent(diff, "", "  ")
		if err != nil {
			return "", err
		}
		return string(raw) + "\n", nil

	case "markdown", "md":
		var b strings.Builder
		fmt.Fprintf(&b, "### SBOM Diff Summary\n\n")
		fmt.Fprintf(&b, "- Old components: `%d` | New components: `%d`\n", diff.OldCount, diff.NewCount)
		fmt.Fprintf(&b, "- Added: `%d` | Removed: `%d` | Version changed: `%d` | License changed: `%d`\n\n",
			len(diff.Added), len(diff.Removed), len(diff.VersionChanged), len(diff.LicenseChanged))
		if !diff.HasChanges() {
			b.WriteString("No component changes detected.\n")
			return b.String(), nil
		}
		b.WriteString("| Change | Ecosystem | Package | From | To |\n| --- | --- | --- | --- | --- |\n")
		for _, c := range diff.Added {
			fmt.Fprintf(&b, "| Added | `%s` | `%s` | - | `%s` |\n", c.Ecosystem, c.Name, c.NewVersion)
		}
		for _, c := range diff.Removed {
			fmt.Fprintf(&b, "| Removed | `%s` | `%s` | `%s` | - |\n", c.Ecosystem, c.Name, c.OldVersion)
		}
		for _, c := range diff.VersionChanged {
			fmt.Fprintf(&b, "| Version | `%s` | `%s` | `%s` | `%s` |\n", c.Ecosystem, c.Name, c.OldVersion, c.NewVersion)
		}
		for _, c := range diff.LicenseChanged {
			fmt.Fprintf(&b, "| License | `%s` | `%s` | `%s` | `%s` |\n", c.Ecosystem, c.Name, emptyDash(c.OldLicense), emptyDash(c.NewLicense))
		}
		return b.String(), nil

	default:
		return "", fmt.Errorf("invalid sbom-diff format %q: expected table, json, or markdown", format)
	}
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}
