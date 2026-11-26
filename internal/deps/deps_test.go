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

	onlineHits, err := AuditDependencies(context.Background(), comps, OSVOptions{Online: true, BaseURL: srv.URL, NoCache: true})
	if err != nil {
		t.Fatalf("AuditDependencies online: %v", err)
	}
	if len(onlineHits) != 1 || onlineHits[0].RuleID != "PIPE-101" || onlineHits[0].Severity != "critical" {
		t.Fatalf("expected 1 critical PIPE-101 online finding, got %+v", onlineHits)
	}
}

func TestExtendedLockfilesLicensesAndOSVCache(t *testing.T) {
	dir := t.TempDir()

	yarnRaw := `# yarn lockfile v1

"lodash@^4.17.20":
  version "4.17.21"
  integrity sha512-v123

"@scope/widget@^1.0.0":
  version "1.2.3"
`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(yarnRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	pnpmRaw := `lockfileVersion: '9.0'
packages:
  chalk@5.3.0:
    resolution: {integrity: sha512-pnpm}
  /@types/node@20.11.0(undici@5.0.0):
    resolution: {integrity: sha512-node}
`
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(pnpmRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	poetryRaw := `[[package]]
name = "urllib3"
version = "2.2.1"
`
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(poetryRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	uvRaw := `version = 1
[[package]]
name = "local-app"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "httpx"
version = "0.27.0"
`
	if err := os.WriteFile(filepath.Join(dir, "uv.lock"), []byte(uvRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	composerRaw := `{
  "packages": [
    {"name": "vendor/copyleft-lib", "version": "v1.4.2", "license": ["GPL-3.0-only"], "dist": {"shasum": "abc123"}},
    {"name": "vendor/safe-lgpl", "version": "2.0.0", "license": ["LGPL-2.1-only"], "dist": {"shasum": "def456"}},
    {"name": "vendor/permissive", "version": "3.1.0", "license": ["MIT"], "dist": {"shasum": "789"}}
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(composerRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	pomRaw := `<project>
  <properties><spring.version>6.1.5</spring.version></properties>
  <dependencies>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-web</artifactId><version>${spring.version}</version></dependency>
    <dependency><groupId>com.example</groupId><artifactId>floating-lib</artifactId><version>LATEST</version></dependency>
  </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pomRaw), 0o600); err != nil {
		t.Fatal(err)
	}

	comps, invFindings, err := InventoryFromPath(dir)
	if err != nil {
		t.Fatalf("InventoryFromPath extended: %v", err)
	}

	purls := make(map[string]bool)
	for _, c := range comps {
		purls[c.PURL] = true
	}
	for _, want := range []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/%40scope/widget@1.2.3",
		"pkg:npm/chalk@5.3.0",
		"pkg:npm/%40types/node@20.11.0",
		"pkg:pypi/urllib3@2.2.1",
		"pkg:pypi/httpx@0.27.0",
		"pkg:composer/vendor/copyleft-lib@1.4.2",
		"pkg:maven/org.springframework/spring-web@6.1.5",
	} {
		if !purls[want] {
			t.Fatalf("missing expected PURL %q from %v", want, purls)
		}
	}
	if purls["pkg:pypi/local-app@0.1.0"] {
		t.Fatalf("local uv.lock workspace root should be skipped")
	}
	if len(invFindings) != 1 || invFindings[0].RuleID != "PIPE-103" {
		t.Fatalf("expected 1 Maven LATEST PIPE-103 finding, got %+v", invFindings)
	}

	licFindings := AuditLicenses(comps, nil)
	if len(licFindings) != 1 || licFindings[0].RuleID != "PIPE-105" || !strings.Contains(licFindings[0].Title, "copyleft-lib") {
		t.Fatalf("expected single PIPE-105 on GPL-3.0-only (not LGPL or MIT), got %+v", licFindings)
	}

	bomJSON, err := GenerateCycloneDX(dir, comps)
	if err != nil || !strings.Contains(bomJSON, `"GPL-3.0-only"`) {
		t.Fatalf("expected CycloneDX SBOM to include license metadata, err=%v bom=%s", err, bomJSON)
	}

	// Parallel OSV detail fetch extracting fixed_version + disk TTL cache verification.
	detailCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-cache-0001"}]}]}`))
		case "/v1/vulns/GHSA-cache-0001":
			detailCalls++
			_, _ = w.Write([]byte(`{
				"id":"GHSA-cache-0001",
				"summary":"Remote issue in mock package",
				"database_specific":{"severity":"HIGH"},
				"affected":[{"package":{"ecosystem":"npm","name":"chalk"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"5.4.0"}]}]}]
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cacheDir := filepath.Join(t.TempDir(), "osv-cache")
	targetComp := []Component{{Ecosystem: "npm", Name: "chalk", Version: "5.3.0", PURL: "pkg:npm/chalk@5.3.0", ManifestPath: "file://pnpm-lock.yaml"}}

	firstHits, err := AuditDependencies(context.Background(), targetComp, OSVOptions{
		Online:   true,
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
	})
	if err != nil || len(firstHits) != 1 || firstHits[0].Evidence["fixed_version"] != "5.4.0" {
		t.Fatalf("first cached OSV lookup failed: hits=%+v err=%v", firstHits, err)
	}
	if detailCalls != 1 {
		t.Fatalf("expected 1 HTTP detail call on cold cache, got %d", detailCalls)
	}

	secondHits, err := AuditDependencies(context.Background(), targetComp, OSVOptions{
		Online:   true,
		BaseURL:  srv.URL,
		CacheDir: cacheDir,
	})
	if err != nil || len(secondHits) != 1 || secondHits[0].Evidence["fixed_version"] != "5.4.0" {
		t.Fatalf("second cached OSV lookup failed: hits=%+v err=%v", secondHits, err)
	}
	if detailCalls != 1 {
		t.Fatalf("expected cache hit with 0 extra HTTP detail calls, total=%d", detailCalls)
	}
}
