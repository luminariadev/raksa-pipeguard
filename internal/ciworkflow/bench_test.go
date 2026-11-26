package ciworkflow

import "testing"

func BenchmarkScanCI(b *testing.B) {
	sample := `
name: Release Audit
on:
  pull_request_target:
permissions: write-all
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: thirdparty/tool@v1
      - run: echo "${{ github.event.issue.title }}"
`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings, err := ScanContent(sample, ".github/workflows/audit.yml")
		if err != nil || len(findings) == 0 {
			b.Fatalf("unexpected benchmark result: findings=%d err=%v", len(findings), err)
		}
	}
}

func BenchmarkScanGitLabCI(b *testing.B) {
	sample := `
stages:
  - build
image: docker:latest
variables:
  DOCKER_TLS_CERTDIR: ""
  API_SECRET_KEY: "hardcodedDemoValue99"
services:
  - docker:dind
build:
  script:
    - curl -sSL https://example.invalid/init.sh | sh
    - printenv
`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings, err := ScanContent(sample, ".gitlab-ci.yml")
		if err != nil || len(findings) == 0 {
			b.Fatalf("unexpected benchmark result: findings=%d err=%v", len(findings), err)
		}
	}
}
