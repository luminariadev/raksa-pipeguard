package deps

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// GenerateSPDX encodes resolved components as an SPDX 2.3 JSON document.
func GenerateSPDX(rootPath string, comps []Component) (string, error) {
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		absRoot = rootPath
	}
	projectName := filepath.Base(absRoot)
	if projectName == "" || projectName == "." || projectName == string(filepath.Separator) {
		projectName = "workspace"
	}

	pkgs := make([]spdxPackage, 0, len(comps))
	rels := make([]spdxRelationship, 0, len(comps))

	for i, c := range comps {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d-%s", i+1, schema.SanitizeIDPart(c.Name))
		lic := strings.TrimSpace(c.License)
		if lic == "" {
			lic = "NOASSERTION"
		}
		pkg := spdxPackage{
			Name:             c.Name,
			SPDXID:           spdxID,
			VersionInfo:      c.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  lic,
		}
		if alg := mapSPDXChecksumAlg(c.HashAlg, c.HashValue); alg != "" {
			pkg.Checksums = []spdxChecksum{{
				Algorithm:     alg,
				ChecksumValue: strings.ToLower(strings.TrimSpace(c.HashValue)),
			}}
		}
		if c.PURL != "" {
			pkg.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  c.PURL,
			}}
		}
		pkgs = append(pkgs, pkg)
		rels = append(rels, spdxRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: spdxID,
		})
	}

	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              projectName,
		DocumentNamespace: "https://spdx.org/spdxdocs/" + schema.ToolName + "-" + randomUUIDv4(),
		CreationInfo: spdxCreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: " + schema.ToolName + "-" + schema.Version},
		},
		Packages:      pkgs,
		Relationships: rels,
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal SPDX 2.3 SBOM: %w", err)
	}
	return string(raw), nil
}

func mapSPDXChecksumAlg(alg, val string) string {
	v := strings.TrimSpace(val)
	if v == "" || strings.HasPrefix(v, "h1:") {
		return ""
	}
	switch strings.ToUpper(strings.TrimSpace(alg)) {
	case "SHA-256", "SHA256":
		return "SHA256"
	case "SHA-512", "SHA512":
		if isHexString(v) {
			return "SHA512"
		}
	case "SHA-1", "SHA1":
		if isHexString(v) {
			return "SHA1"
		}
	}
	return ""
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
