package iac

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

type tfIngressBlock struct {
	openLine int
	fromPort int
	toPort   int
	hasFrom  bool
	hasTo    bool
	openCIDR bool
	protocol string
}

func LintTerraform(content string, target string) []schema.Finding {
	now := time.Now().UTC()
	var findings []schema.Finding
	var curIngress *tfIngressBlock

	for idx, rawLine := range strings.Split(content, "\n") {
		lineNo := idx + 1
		line := stripTFComment(rawLine)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)

		if curIngress == nil && (strings.HasPrefix(low, "ingress {") || low == "ingress{" || strings.Contains(low, "ingress {")) {
			curIngress = &tfIngressBlock{openLine: lineNo}
			continue
		}

		if curIngress != nil {
			if strings.Contains(line, "}") {
				if curIngress.openCIDR && coversSensitiveMgmtPort(curIngress) {
					findings = append(findings, schema.NewFinding(
						"PIPE-304", "iac", schema.SeverityHigh,
						"Terraform security group opens management ports (SSH/RDP/all) to 0.0.0.0/0",
						fmt.Sprintf("Ingress block starting on line %d exposes SSH/RDP or all ports to public Internet CIDR.", curIngress.openLine),
						target,
						map[string]any{"line": curIngress.openLine, "from_port": curIngress.fromPort, "to_port": curIngress.toPort, "standard": "CIS Cloud Benchmark"},
						"Restrict ingress CIDR blocks strictly to corporate VPN/bastion IPs or remove direct SSH/RDP exposure.",
						"D3-CH", fmt.Sprintf("tf-l%d-sg", curIngress.openLine), now,
					))
				}
				curIngress = nil
				continue
			}

			if strings.Contains(low, "0.0.0.0/0") || strings.Contains(low, "::/0") {
				curIngress.openCIDR = true
			}
			if val, ok := parseTFAssign(low, "from_port"); ok {
				if p, err := strconv.Atoi(val); err == nil {
					curIngress.fromPort = p
					curIngress.hasFrom = true
				}
			}
			if val, ok := parseTFAssign(low, "to_port"); ok {
				if p, err := strconv.Atoi(val); err == nil {
					curIngress.toPort = p
					curIngress.hasTo = true
				}
			}
			if val, ok := parseTFAssign(low, "protocol"); ok {
				curIngress.protocol = strings.Trim(val, `"'`)
			}
			continue
		}

		// Public S3 bucket ACL or disabled public access block
		if val, ok := parseTFAssign(low, "acl"); ok {
			cleaned := strings.Trim(val, `"'`)
			if cleaned == "public-read" || cleaned == "public-read-write" || cleaned == "authenticated-read" {
				findings = append(findings, schema.NewFinding(
					"PIPE-304", "iac", schema.SeverityHigh,
					"Terraform configures publicly accessible S3 bucket ACL",
					fmt.Sprintf("Directive acl = %q on line %d exposes storage bucket globally.", cleaned, lineNo),
					target,
					map[string]any{"line": lineNo, "acl": cleaned, "standard": "CIS Cloud Benchmark"},
					"Set acl = \"private\" and attach aws_s3_bucket_public_access_block with all four blocks true.",
					"D3-CH", fmt.Sprintf("tf-l%d-s3acl", lineNo), now,
				))
			}
		}

		for _, key := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
			if val, ok := parseTFAssign(low, key); ok && strings.Trim(val, `"'`) == "false" {
				findings = append(findings, schema.NewFinding(
					"PIPE-304", "iac", schema.SeverityHigh,
					"Terraform disables S3 public access block safeguard",
					fmt.Sprintf("Setting %s = false on line %d allows public bucket exposure.", key, lineNo),
					target,
					map[string]any{"line": lineNo, "setting": key, "value": "false", "standard": "CIS Cloud Benchmark"},
					fmt.Sprintf("Set %s = true in aws_s3_bucket_public_access_block.", key),
					"D3-CH", fmt.Sprintf("tf-l%d-s3blk-%s", lineNo, key), now,
				))
			}
		}

		// Disabled storage/volume/DB encryption
		for _, encKey := range []string{"encrypted", "storage_encrypted", "enable_encryption"} {
			if val, ok := parseTFAssign(low, encKey); ok && strings.Trim(val, `"'`) == "false" {
				findings = append(findings, schema.NewFinding(
					"PIPE-304", "iac", schema.SeverityHigh,
					"Terraform disables encryption at rest",
					fmt.Sprintf("Setting %s = false on line %d leaves storage unencrypted.", encKey, lineNo),
					target,
					map[string]any{"line": lineNo, "setting": encKey, "value": "false", "standard": "CIS Cloud Benchmark"},
					fmt.Sprintf("Set %s = true (optionally referencing a customer-managed KMS key).", encKey),
					"D3-CH", fmt.Sprintf("tf-l%d-enc", lineNo), now,
				))
			}
		}
	}

	return findings
}

func coversSensitiveMgmtPort(in *tfIngressBlock) bool {
	if in.protocol == "-1" || strings.EqualFold(in.protocol, "all") {
		return true
	}
	if !in.hasFrom && !in.hasTo {
		return false
	}
	lo, hi := in.fromPort, in.toPort
	if !in.hasTo {
		hi = lo
	}
	if !in.hasFrom {
		lo = hi
	}
	if lo == 0 && hi == 0 {
		return true
	}
	return (lo <= 22 && hi >= 22) || (lo <= 3389 && hi >= 3389)
}

func parseTFAssign(lowLine, key string) (string, bool) {
	eq := strings.IndexByte(lowLine, '=')
	if eq <= 0 {
		return "", false
	}
	lhs := strings.TrimSpace(lowLine[:eq])
	if lhs != key {
		return "", false
	}
	return strings.TrimSpace(lowLine[eq+1:]), true
}

func stripTFComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == quote && (i == 0 || line[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '#' {
			return strings.TrimSpace(line[:i])
		}
		if c == '/' && i+1 < len(line) && line[i+1] == '/' {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}
