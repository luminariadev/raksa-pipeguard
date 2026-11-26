package deps

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

type cyclonedxBOM struct {
	BOMFormat    string        `json:"bomFormat"`
	SpecVersion  string        `json:"specVersion"`
	SerialNumber string        `json:"serialNumber"`
	Version      int           `json:"version"`
	Metadata     cycloneMeta   `json:"metadata"`
	Components   []cycloneComp `json:"components"`
}

type cycloneMeta struct {
	Timestamp string       `json:"timestamp"`
	Tools     cycloneTools `json:"tools"`
	Component cycloneRoot  `json:"component"`
}

type cycloneTools struct {
	Components []cycloneRoot `json:"components"`
}

type cycloneRoot struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cycloneComp struct {
	Type    string        `json:"type"`
	BOMRef  string        `json:"bom-ref"`
	Name    string        `json:"name"`
	Version string        `json:"version"`
	PURL    string        `json:"purl"`
	Hashes  []cycloneHash `json:"hashes,omitempty"`
}

type cycloneHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

func GenerateCycloneDX(rootPath string, comps []Component) (string, error) {
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		absRoot = rootPath
	}
	projectName := filepath.Base(absRoot)
	if projectName == "" || projectName == "." || projectName == string(filepath.Separator) {
		projectName = "workspace"
	}

	outComps := make([]cycloneComp, 0, len(comps))
	for _, c := range comps {
		item := cycloneComp{
			Type:    "library",
			BOMRef:  c.PURL,
			Name:    c.Name,
			Version: c.Version,
			PURL:    c.PURL,
		}
		if c.HashAlg != "" && c.HashValue != "" {
			item.Hashes = []cycloneHash{{Alg: c.HashAlg, Content: c.HashValue}}
		}
		outComps = append(outComps, item)
	}

	bom := cyclonedxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + randomUUIDv4(),
		Version:      1,
		Metadata: cycloneMeta{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: cycloneTools{
				Components: []cycloneRoot{
					{
						Type:    "application",
						Name:    schema.ToolName,
						Version: schema.Version,
					},
				},
			},
			Component: cycloneRoot{
				Type: "application",
				Name: projectName,
			},
		},
		Components: outComps,
	}

	encoded, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode CycloneDX 1.5 SBOM: %w", err)
	}
	return string(encoded) + "\n", nil
}

func randomUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
