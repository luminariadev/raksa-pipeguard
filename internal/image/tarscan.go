package image

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/deps"
	"github.com/luminariadev/raksa-pipeguard/internal/schema"
	"github.com/luminariadev/raksa-pipeguard/internal/secrets"
)

const (
	MaxTarUnpackedBytes int64 = 512 * 1024 * 1024
	MaxTarEntryBytes    int64 = 32 * 1024 * 1024
)

type ImageScanResult struct {
	ImageRef   string           `json:"image_ref"`
	Format     string           `json:"format"`
	Components []deps.Component `json:"components"`
	Findings   []schema.Finding `json:"findings"`
}

type dockerSaveManifestItem struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type ociIndex struct {
	Manifests []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
	} `json:"manifests"`
}

type ociManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

type imageConfigJSON struct {
	Config struct {
		User string   `json:"User"`
		Env  []string `json:"Env"`
	} `json:"config"`
}

// ScanTarball inspects a Docker save (`docker save`) or OCI layout tarball for OS packages and runtime misconfigurations.
func ScanTarball(tarPath string) (ImageScanResult, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return ImageScanResult{}, fmt.Errorf("open image archive %q: %w", tarPath, err)
	}
	defer f.Close()

	r, closeExtra, err := openTarMaybeGzip(f)
	if err != nil {
		return ImageScanResult{}, fmt.Errorf("open tar stream %q: %w", tarPath, err)
	}
	if closeExtra != nil {
		defer closeExtra.Close()
	}

	// Pass 1: read image metadata/indexes and buffer bounded tar archive offsets or layer paths cleanly.
	// To avoid loading huge multi-GB layers in memory, inspect metadata first and store only metadata JSON + layer blobs up to limits.
	topEntries := make(map[string][]byte)
	var totalRead int64

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ImageScanResult{}, fmt.Errorf("read tar header %q: %w", tarPath, err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		clean := normalizeArchivePath(hdr.Name)
		if hdr.Size > MaxTarEntryBytes {
			// Skip oversized entries from Pass 1 metadata buffer; layers stream cleanly in Pass 2.
			continue
		}
		if totalRead+hdr.Size > MaxTarUnpackedBytes {
			return ImageScanResult{}, fmt.Errorf("image archive %q exceeds %d byte safety budget", tarPath, MaxTarUnpackedBytes)
		}
		if isImageMetadataFile(clean, hdr.Size) {
			data, readErr := readBoundedEntry(tr, hdr.Size)
			if readErr != nil {
				return ImageScanResult{}, readErr
			}
			totalRead += int64(len(data))
			topEntries[clean] = data
		}
	}

	target := "image://" + filepath.ToSlash(tarPath)
	cfgPath, layerPaths, imageRef, formatName, err := resolveImageStructure(topEntries, tarPath)
	if err != nil {
		return ImageScanResult{}, err
	}

	var findings []schema.Finding
	now := time.Now().UTC()

	if cfgBytes, ok := topEntries[cfgPath]; ok {
		findings = append(findings, auditImageConfig(cfgBytes, imageRef, target, now)...)
	}

	// Pass 2: stream layer entries in manifest order so large images do not exceed memory limits.
	if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
		return ImageScanResult{}, fmt.Errorf("rewind image archive %q: %w", tarPath, seekErr)
	}
	r2, closeExtra2, err := openTarMaybeGzip(f)
	if err != nil {
		return ImageScanResult{}, fmt.Errorf("re-open tar stream %q: %w", tarPath, err)
	}
	if closeExtra2 != nil {
		defer closeExtra2.Close()
	}

	layerWant := make(map[string]int, len(layerPaths))
	for i, lp := range layerPaths {
		layerWant[normalizeArchivePath(lp)] = i
	}

	snapshots := make([]layerSnapshot, len(layerPaths))
	tr2 := tar.NewReader(r2)
	var layerStreamBudget int64

	for {
		hdr, err := tr2.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ImageScanResult{}, fmt.Errorf("read layer stream %q: %w", tarPath, err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		clean := normalizeArchivePath(hdr.Name)
		idx, needed := layerWant[clean]
		if !needed {
			continue
		}
		if layerStreamBudget+hdr.Size > MaxTarUnpackedBytes {
			return ImageScanResult{}, fmt.Errorf("image layers in %q exceed %d byte safety limit", tarPath, MaxTarUnpackedBytes)
		}
		layerStreamBudget += hdr.Size
		snap, lErr := captureLayerPkgDBs(tr2)
		if lErr != nil {
			return ImageScanResult{}, fmt.Errorf("inspect layer %q: %w", clean, lErr)
		}
		snapshots[idx] = snap
	}

	pkgDBFiles := mergeLayerSnapshots(snapshots)
	comps := parseCollectedPkgDBs(pkgDBFiles, target)
	return ImageScanResult{
		ImageRef:   imageRef,
		Format:     formatName,
		Components: comps,
		Findings:   findings,
	}, nil
}

func openTarMaybeGzip(f *os.File) (io.Reader, io.Closer, error) {
	br := bufio.NewReaderSize(f, 32*1024)
	magic, err := br.Peek(2)
	if err == nil && len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gErr := gzip.NewReader(br)
		if gErr != nil {
			return nil, nil, gErr
		}
		return gz, gz, nil
	}
	return br, nil, nil
}

func openStreamMaybeGzip(r io.Reader) (io.Reader, io.Closer, error) {
	br := bufio.NewReaderSize(r, 16*1024)
	magic, err := br.Peek(2)
	if err == nil && len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gErr := gzip.NewReader(br)
		if gErr != nil {
			return nil, nil, gErr
		}
		return gz, gz, nil
	}
	return br, nil, nil
}

func isImageMetadataFile(clean string, size int64) bool {
	if clean == "manifest.json" || clean == "index.json" || clean == "oci-layout" || strings.HasSuffix(clean, ".json") {
		return size <= 2*1024*1024
	}
	return strings.HasPrefix(clean, "blobs/sha256/") && size <= 512*1024
}

func resolveImageStructure(entries map[string][]byte, fallbackName string) (cfgPath string, layers []string, imageRef, formatName string, err error) {
	imageRef = filepath.Base(fallbackName)

	if rawManifest, ok := entries["manifest.json"]; ok {
		var items []dockerSaveManifestItem
		if jErr := json.Unmarshal(rawManifest, &items); jErr == nil && len(items) > 0 {
			it := items[0]
			if len(it.RepoTags) > 0 && it.RepoTags[0] != "" {
				imageRef = it.RepoTags[0]
			}
			normLayers := make([]string, 0, len(it.Layers))
			for _, l := range it.Layers {
				normLayers = append(normLayers, normalizeArchivePath(l))
			}
			return normalizeArchivePath(it.Config), normLayers, imageRef, "docker-save", nil
		}
	}

	if rawIndex, ok := entries["index.json"]; ok {
		var idx ociIndex
		if jErr := json.Unmarshal(rawIndex, &idx); jErr == nil && len(idx.Manifests) > 0 {
			mDigest := idx.Manifests[0].Digest
			mPath := digestToBlobPath(mDigest)
			rawMan, okM := entries[mPath]
			if !okM {
				return "", nil, "", "", fmt.Errorf("missing OCI manifest blob %q", mPath)
			}
			var man ociManifest
			if err := json.Unmarshal(rawMan, &man); err != nil {
				return "", nil, "", "", fmt.Errorf("parse OCI manifest %q: %w", mPath, err)
			}
			for _, l := range man.Layers {
				layers = append(layers, digestToBlobPath(l.Digest))
			}
			return digestToBlobPath(man.Config.Digest), layers, imageRef, "oci-layout", nil
		}
	}

	return "", nil, "", "", fmt.Errorf("unsupported container archive %q: expected Docker manifest.json or OCI index.json", fallbackName)
}

func digestToBlobPath(digest string) string {
	trimmed := strings.TrimSpace(digest)
	if strings.HasPrefix(trimmed, "sha256:") {
		return "blobs/sha256/" + strings.TrimPrefix(trimmed, "sha256:")
	}
	return normalizeArchivePath(trimmed)
}

func auditImageConfig(cfgBytes []byte, imageRef, target string, now time.Time) []schema.Finding {
	var cfg imageConfigJSON
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil
	}
	var findings []schema.Finding
	u := strings.ToLower(strings.TrimSpace(cfg.Config.User))
	if u == "" || u == "root" || u == "0" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:") {
		findings = append(findings, schema.NewFinding(
			"PIPE-201", "iac", schema.SeverityHigh,
			"Container image config defaults to root runtime user",
			fmt.Sprintf("Image %q sets User=%q (runs as UID 0 by default).", imageRef, cfg.Config.User),
			target,
			map[string]any{"image_ref": imageRef, "user": cfg.Config.User, "standard": "CIS Docker 4.1"},
			"Set a non-root USER (e.g., USER nonroot:nonroot or USER 10001:10001) in the final Dockerfile stage.",
			"D3-CH", "img-config-root-user", now,
		))
	}

	for idx, envEntry := range cfg.Config.Env {
		eq := strings.IndexByte(envEntry, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(envEntry[:eq])
		val := strings.TrimSpace(envEntry[eq+1:])
		if val == "" || strings.EqualFold(key, "PATH") {
			continue
		}
		kUp := strings.ToUpper(key)
		hasSensitiveKey := false
		for _, kw := range []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY", "PRIVATE_KEY"} {
			if strings.Contains(kUp, kw) {
				hasSensitiveKey = true
				break
			}
		}
		secHits := secrets.ScanContent(envEntry, target+"#env", secrets.ScanOptions{})
		if (hasSensitiveKey && !secrets.IsPlaceholderSecret(val)) || len(secHits) > 0 {
			findings = append(findings, schema.NewFinding(
				"PIPE-203", "iac", schema.SeverityHigh,
				"Container image config bakes sensitive credential in Env",
				fmt.Sprintf("Image %q exposes credential variable %q inside runtime Env configuration (value redacted).", imageRef, key),
				target,
				map[string]any{
					"image_ref":      imageRef,
					"env_key":        key,
					"env_index":      idx,
					"redacted_match": secrets.MaskSecret(val),
					"standard":       "CIS Docker 4.10",
				},
				"Remove baked credentials from image ENV/ARG and inject secrets dynamically at container runtime.",
				"D3-KM", fmt.Sprintf("img-env-%d-%s", idx, key), now,
			))
		}
	}

	return findings
}

type layerSnapshot struct {
	opaques []string
	deletes []string
	files   map[string][]byte
}

func captureLayerPkgDBs(layerStream io.Reader) (layerSnapshot, error) {
	snap := layerSnapshot{files: make(map[string][]byte)}
	sr, closer, err := openStreamMaybeGzip(layerStream)
	if err != nil {
		return snap, err
	}
	if closer != nil {
		defer closer.Close()
	}

	tr := tar.NewReader(sr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return snap, nil
		}
		if err != nil {
			// Skip unreadable non-tar blobs cleanly.
			return snap, nil
		}
		clean := normalizeArchivePath(hdr.Name)
		base := path.Base(clean)
		dir := path.Dir(clean)

		if base == ".wh..wh..opq" {
			prefix := ""
			if dir != "." {
				prefix = dir + "/"
			}
			snap.opaques = append(snap.opaques, prefix)
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			deletedName := strings.TrimPrefix(base, ".wh.")
			targetDel := deletedName
			if dir != "." {
				targetDel = dir + "/" + deletedName
			}
			snap.deletes = append(snap.deletes, targetDel)
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if isOSPackageDBPath(clean) && hdr.Size <= MaxTarEntryBytes {
			data, rErr := readBoundedEntry(tr, hdr.Size)
			if rErr != nil {
				return snap, rErr
			}
			snap.files[clean] = data
		}
	}
}

func mergeLayerSnapshots(snaps []layerSnapshot) map[string][]byte {
	merged := make(map[string][]byte)
	for _, snap := range snaps {
		for _, prefix := range snap.opaques {
			for existing := range merged {
				if prefix == "" || strings.HasPrefix(existing, prefix) {
					delete(merged, existing)
				}
			}
		}
		for _, delPath := range snap.deletes {
			delete(merged, delPath)
		}
		for k, v := range snap.files {
			merged[k] = v
		}
	}
	return merged
}

func isOSPackageDBPath(clean string) bool {
	return clean == "lib/apk/db/installed" ||
		clean == "var/lib/dpkg/status" ||
		strings.HasPrefix(clean, "var/lib/dpkg/status.d/")
}

func parseCollectedPkgDBs(pkgDBFiles map[string][]byte, target string) []deps.Component {
	var comps []deps.Component
	seenPURL := make(map[string]struct{})
	add := func(c deps.Component) {
		if c.Name == "" || c.Version == "" {
			return
		}
		if _, dup := seenPURL[c.PURL]; dup {
			return
		}
		seenPURL[c.PURL] = struct{}{}
		comps = append(comps, c)
	}

	paths := make([]string, 0, len(pkgDBFiles))
	for p := range pkgDBFiles {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		raw := string(pkgDBFiles[p])
		if p == "lib/apk/db/installed" {
			for _, c := range parseAPKInstalled(raw, target+"#/"+p) {
				add(c)
			}
		} else if p == "var/lib/dpkg/status" || strings.HasPrefix(p, "var/lib/dpkg/status.d/") {
			for _, c := range parseDPKGStatus(raw, target+"#/"+p) {
				add(c)
			}
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
	return comps
}

func parseAPKInstalled(raw, target string) []deps.Component {
	var comps []deps.Component
	var name, ver, lic, sum string
	flush := func() {
		if name != "" && ver != "" {
			c := deps.Component{
				Ecosystem:    "Alpine",
				Name:         name,
				Version:      ver,
				PURL:         fmt.Sprintf("pkg:apk/alpine/%s@%s", name, ver),
				ManifestPath: target,
				License:      lic,
			}
			if sum != "" {
				c.HashAlg = "SHA-1"
				c.HashValue = sum
			}
			comps = append(comps, c)
		}
		name, ver, lic, sum = "", "", "", ""
	}

	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "P:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "P:"))
		case strings.HasPrefix(line, "V:"):
			ver = strings.TrimSpace(strings.TrimPrefix(line, "V:"))
		case strings.HasPrefix(line, "L:"):
			lic = strings.TrimSpace(strings.TrimPrefix(line, "L:"))
		case strings.HasPrefix(line, "C:Q1"):
			sum = strings.TrimSpace(strings.TrimPrefix(line, "C:"))
		}
	}
	flush()
	return comps
}

func parseDPKGStatus(raw, target string) []deps.Component {
	var comps []deps.Component
	var pkg, ver, status string
	flush := func() {
		if pkg != "" && ver != "" {
			if status == "" || strings.HasSuffix(strings.ToLower(strings.TrimSpace(status)), "installed") {
				comps = append(comps, deps.Component{
					Ecosystem:    "Debian",
					Name:         pkg,
					Version:      ver,
					PURL:         fmt.Sprintf("pkg:deb/debian/%s@%s", pkg, ver),
					ManifestPath: target,
				})
			}
		}
		pkg, ver, status = "", "", ""
	}

	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "Package:"):
			pkg = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case strings.HasPrefix(line, "Version:"):
			ver = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Status:"):
			status = strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
		}
	}
	flush()
	return comps
}

func readBoundedEntry(r io.Reader, size int64) ([]byte, error) {
	capBytes := size
	if capBytes < 0 || capBytes > MaxTarEntryBytes {
		capBytes = MaxTarEntryBytes
	}
	return io.ReadAll(io.LimitReader(r, capBytes))
}

func normalizeArchivePath(p string) string {
	clean := path.Clean(strings.ReplaceAll(p, `\`, "/"))
	clean = strings.TrimPrefix(clean, "./")
	clean = strings.TrimPrefix(clean, "/")
	return clean
}
