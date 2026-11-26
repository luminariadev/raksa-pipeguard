package secrets

import "testing"

const benchCleanGoSource = `package service

import (
	"fmt"
	"net/http"
)

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, "{\"status\":\"ok\"}")
}
`

func BenchmarkScanSecrets(b *testing.B) {
	opts := ScanOptions{EntropyThreshold: DefaultMinEntropy}
	for i := 0; i < b.N; i++ {
		_ = ScanContent(benchCleanGoSource, "file://service.go", opts)
	}
}
