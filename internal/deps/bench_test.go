package deps

import "testing"

func BenchmarkGenerateSBOM(b *testing.B) {
	comps := []Component{
		{Ecosystem: "Go", Name: "gopkg.in/yaml.v3", Version: "v3.0.1", PURL: "pkg:golang/gopkg.in/yaml.v3@v3.0.1", HashAlg: "SHA-256", HashValue: "h1:demo"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		{Ecosystem: "crates.io", Name: "serde", Version: "1.0.210", PURL: "pkg:cargo/serde@1.0.210"},
		{Ecosystem: "PyPI", Name: "requests", Version: "2.32.3", PURL: "pkg:pypi/requests@2.32.3"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateCycloneDX("/workspace/app", comps)
	}
}
