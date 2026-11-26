package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func buildLayerTar(t *testing.T, files map[string]string, gzipLayer bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	var tw *tar.Writer
	var gw *gzip.Writer
	if gzipLayer {
		gw = gzip.NewWriter(&buf)
		tw = tar.NewWriter(gw)
	} else {
		tw = tar.NewWriter(&buf)
	}

	for name, body := range files {
		b := []byte(body)
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(b)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if gw != nil {
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func writeOuterTar(t *testing.T, outPath string, entries map[string][]byte) {
	t.Helper()
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for name, data := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestScanTarballDockerSaveAndOCILayout(t *testing.T) {
	dir := t.TempDir()

	// 1. Docker save archive: root User + Env secret + Alpine APK DB
	apkDB := "P:busybox\nV:1.36.1-r29\nL:GPL-2.0-only\n\nP:openssl\nV:3.1.4-r0\nL:Apache-2.0\n\n"
	layer1 := buildLayerTar(t, map[string]string{
		"lib/apk/db/installed": apkDB,
	}, false)

	secretVal := "MySuperSecretLayerPass99"
	cfgRaw, _ := json.Marshal(map[string]any{
		"config": map[string]any{
			"User": "",
			"Env":  []string{"PATH=/usr/bin", "DB_PASSWORD=" + secretVal},
		},
	})
	manifestRaw, _ := json.Marshal([]map[string]any{
		{
			"Config":   "config.json",
			"RepoTags": []string{"demo/app:0.1.0"},
			"Layers":   []string{"layer1/layer.tar"},
		},
	})

	dockerTar := filepath.Join(dir, "docker-save.tar")
	writeOuterTar(t, dockerTar, map[string][]byte{
		"manifest.json":    manifestRaw,
		"config.json":      cfgRaw,
		"layer1/layer.tar": layer1,
	})

	res, err := ScanTarball(dockerTar)
	if err != nil {
		t.Fatalf("ScanTarball docker-save failed: %v", err)
	}
	if len(res.Components) != 2 || res.Components[0].Ecosystem != "Alpine" {
		t.Fatalf("expected 2 Alpine components, got %+v", res.Components)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings (PIPE-201 root user + PIPE-203 Env secret), got %+v", res.Findings)
	}
	rawJSON, _ := json.Marshal(res)
	if bytes.Contains(rawJSON, []byte(secretVal)) {
		t.Fatalf("raw Env secret leaked into image findings")
	}

	// 2. OCI Layout tarball: distroless nonroot User + gzipped Debian status.d packages
	ociCfg, _ := json.Marshal(map[string]any{
		"config": map[string]any{
			"User": "nonroot:nonroot",
			"Env":  []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		},
	})
	ociLayer := buildLayerTar(t, map[string]string{
		"var/lib/dpkg/status.d/tzdata": "Package: tzdata\nVersion: 2024a-0+deb12u1\n",
	}, true)

	sumHex := func(b []byte) string {
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:])
	}
	cfgHex := sumHex(ociCfg)
	layerHex := sumHex(ociLayer)

	ociMan, _ := json.Marshal(map[string]any{
		"config": map[string]any{"digest": "sha256:" + cfgHex},
		"layers": []map[string]any{{"digest": "sha256:" + layerHex}},
	})
	manHex := sumHex(ociMan)
	ociIdx, _ := json.Marshal(map[string]any{
		"manifests": []map[string]any{{"digest": "sha256:" + manHex}},
	})

	ociTar := filepath.Join(dir, "oci-image.tar")
	writeOuterTar(t, ociTar, map[string][]byte{
		"index.json":               ociIdx,
		"blobs/sha256/" + manHex:   ociMan,
		"blobs/sha256/" + cfgHex:   ociCfg,
		"blobs/sha256/" + layerHex: ociLayer,
	})

	ociRes, err := ScanTarball(ociTar)
	if err != nil {
		t.Fatalf("ScanTarball OCI layout failed: %v", err)
	}
	if len(ociRes.Findings) != 0 {
		t.Fatalf("expected 0 findings on distroless nonroot OCI archive, got %+v", ociRes.Findings)
	}
	if len(ociRes.Components) != 1 || ociRes.Components[0].Ecosystem != "Debian" || ociRes.Components[0].Name != "tzdata" {
		t.Fatalf("expected 1 Debian tzdata component, got %+v", ociRes.Components)
	}
}
