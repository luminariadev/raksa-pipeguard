package deps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventoryCycloneDXAndUnpinnedFindings(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/app\n\ngo 1.24\n\nrequire gopkg.in/yaml.v3 v3.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLH3ezI9Ks6/XgN/wqN/01Wpq8s2q30=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"lodash":"4.17.20","badpkg":"latest"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/lodash":{"version":"4.17.20","integrity":"sha512-abc"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte("[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nchecksum = \"deadbeef\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.31.0\nflask>=2.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	comps, findings, err := InventoryFromPath(dir)
	if err != nil {
		t.Fatalf("InventoryFromPath: %v", err)
	}
	if len(comps) != 4 {
		t.Fatalf("expected 4 pinned components across 4 ecosystems, got %d: %+v", len(comps), comps)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 PIPE-103 unpinned findings (badpkg, flask), got %+v", findings)
	}

	bomJSON, err := GenerateCycloneDX(dir, comps)
	if err != nil {
		t.Fatal(err)
	}
	var bom map[string]any
	if err := json.Unmarshal([]byte(bomJSON), &bom); err != nil {
		t.Fatal(err)
	}
	if bom["bomFormat"] != "CycloneDX" || bom["specVersion"] != "1.5" {
		t.Fatalf("unexpected BOM header: %+v", bom)
	}
	if !strings.Contains(bomJSON, "pkg:golang/gopkg.in/yaml.v3@v3.0.1") || !strings.Contains(bomJSON, "pkg:pypi/requests@2.31.0") {
		t.Fatalf("missing expected PURLs in SBOM: %s", bomJSON)
	}
}

func TestOfflineAndOnlineOSVAudit(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "offline_osv.json")
	dbRaw := `{
  "vulnerabilities": [
    {
      "id": "GHSA-35jh-r3h4-6jhm",
      "ecosystem": "npm",
      "package": "lodash",
      "affected_versions": ["4.17.20"],
      "severity": "high",
      "summary": "Command Injection in lodash",
      "fixed_version": "4.17.21"
    },
    {
      "id": "PYSEC-2023-74",
      "ecosystem": "PyPI",
      "package": "requests",
      "affected_versions": ["2.31.0"],
      "severity": "medium",
      "summary": "Unintended Proxy-Authorization leak",
      "fixed_version": "2.32.0"
    }
  ]
}`
	if err := os.WriteFile(dbPath, []byte(dbRaw), 0o600); err != nil {
		t.Fatal(err)
	}

	comps := []Component{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20", ManifestPath: "file://package-lock.json"},
		{Ecosystem: "PyPI", Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0", ManifestPath: "file://requirements.txt"},
	}

	offlineHits, err := AuditDependencies(context.Background(), comps, OSVOptions{OfflineDBPath: dbPath})
	if err != nil {
		t.Fatalf("AuditDependencies offline: %v", err)
	}
	if len(offlineHits) != 2 || offlineHits[0].RuleID != "PIPE-101" || offlineHits[1].RuleID != "PIPE-102" {
		t.Fatalf("expected PIPE-101 and PIPE-102 from offline DB, got %+v", offlineHits)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-test-online"}]},{"vulns":[]}]}`))
		case "/v1/vulns/GHSA-test-online":
			_, _ = w.Write([]byte(`{"summary":"Critical online mock flaw","database_specific":{"severity":"CRITICAL"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	onlineHits, err := AuditDependencies(context.Background(), comps, OSVOptions{Online: true, BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("AuditDependencies online: %v", err)
	}
	if len(onlineHits) != 1 || onlineHits[0].RuleID != "PIPE-101" || onlineHits[0].Severity != "critical" {
		t.Fatalf("expected 1 critical PIPE-101 online finding, got %+v", onlineHits)
	}
}
