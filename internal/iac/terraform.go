package iac

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

var (
	tfResourceHdrRe = regexp.MustCompile(`^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)
	tfVarHdrRe      = regexp.MustCompile(`^variable\s+"([^"]+)"\s*\{`)
	tfVarRefRe      = regexp.MustCompile(`\b(?:var|local)\.([A-Za-z0-9_]+)\b`)
	tfQuotedStrRe   = regexp.MustCompile(`"([^"]*)"`)
	tfIntTokenRe    = regexp.MustCompile(`\b(\d{1,5})\b`)
)

type tfBlock struct {
	kind       string
	resType    string
	resName    string
	openLine   int
	attrs      map[string]string
	allows     []tfAllowRule
	secRules   []map[string]string
	statements []tfStatement
	isWildcard bool
}

type tfAllowRule struct {
	line     int
	protocol string
	ports    string
}

type tfStatement struct {
	line      int
	effect    string
	actions   string
	resources string
}

// LintTerraform audits AWS, GCP, and Azure Terraform HCL configurations including var/local defaults.
func LintTerraform(content string, target string) []schema.Finding {
	lines := prepareTFLines(content)
	if len(lines) == 0 {
		return nil
	}

	bindings := collectTFBindings(lines)
	now := time.Now().UTC()
	var (
		findings []schema.Finding
		stack    []*tfBlock
		pending  string
	)

	flushAssign := func(stmt string, lineNo int) {
		key, val, ok := parseTFAssignRaw(stmt)
		if !ok || len(stack) == 0 {
			return
		}
		resolved := resolveTFExpr(val, bindings)
		lowKey := strings.ToLower(key)
		lowRes := strings.ToLower(resolved)
		cur := stack[len(stack)-1]
		cur.attrs[lowKey] = lowRes

		// Direct per-line AWS safeguards kept cleanly scoped to resource lines.
		switch lowKey {
		case "acl":
			cleaned := strings.Trim(lowRes, `"' `)
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
		case "block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets":
			if strings.Trim(lowRes, `"' `) == "false" {
				findings = append(findings, schema.NewFinding(
					"PIPE-304", "iac", schema.SeverityHigh,
					"Terraform disables S3 public access block safeguard",
					fmt.Sprintf("Setting %s = false on line %d allows public bucket exposure.", lowKey, lineNo),
					target,
					map[string]any{"line": lineNo, "setting": lowKey, "value": "false", "standard": "CIS Cloud Benchmark"},
					fmt.Sprintf("Set %s = true in aws_s3_bucket_public_access_block.", lowKey),
					"D3-CH", fmt.Sprintf("tf-l%d-s3blk-%s", lineNo, lowKey), now,
				))
			}
		case "encrypted", "storage_encrypted", "enable_encryption":
			if strings.Trim(lowRes, `"' `) == "false" {
				findings = append(findings, schema.NewFinding(
					"PIPE-304", "iac", schema.SeverityHigh,
					"Terraform disables encryption at rest",
					fmt.Sprintf("Setting %s = false on line %d leaves storage unencrypted.", lowKey, lineNo),
					target,
					map[string]any{"line": lineNo, "setting": lowKey, "value": "false", "standard": "CIS Cloud Benchmark"},
					fmt.Sprintf("Set %s = true (optionally referencing a customer-managed KMS key).", lowKey),
					"D3-CH", fmt.Sprintf("tf-l%d-enc", lineNo), now,
				))
			}
		}

		// Inline JSON IAM policy check on `policy = ...`.
		if lowKey == "policy" && strings.Contains(lowRes, `"*"`) && strings.Contains(lowRes, "action") && strings.Contains(lowRes, "resource") {
			if (strings.Contains(lowRes, `"action": "*"`) || strings.Contains(lowRes, `"action":"*"`) ||
				strings.Contains(lowRes, `"action": ["*"]`) || strings.Contains(lowRes, `"action":["*"]`)) &&
				(strings.Contains(lowRes, `"resource": "*"`) || strings.Contains(lowRes, `"resource":"*"`) ||
					strings.Contains(lowRes, `"resource": ["*"]`) || strings.Contains(lowRes, `"resource":["*"]`)) &&
				!strings.Contains(lowRes, `"deny"`) {
				findings = append(findings, schema.NewFinding(
					"PIPE-304", "iac", schema.SeverityHigh,
					"Terraform IAM policy grants wildcard '*' actions on '*' resources",
					fmt.Sprintf("IAM policy attribute on line %d grants unrestricted administrative permissions.", lineNo),
					target,
					map[string]any{"line": lineNo, "standard": "CIS Cloud Benchmark"},
					"Scope IAM Action and Resource fields strictly to required services and resource ARNs.",
					"D3-CH", fmt.Sprintf("tf-l%d-iam-wildcard", lineNo), now,
				))
			}
		}
	}

	bracketDepth := 0
	pendingStartLine := 0

	for idx, line := range lines {
		lineNo := idx + 1
		if line == "" {
			continue
		}

		// Accumulate multi-line list/heredoc assignment expressions safely.
		if pending != "" {
			pending += " " + line
			bracketDepth += netBracketDelta(line)
			if bracketDepth <= 0 {
				flushAssign(pending, pendingStartLine)
				pending = ""
				bracketDepth = 0
			}
			continue
		}

		if strings.HasSuffix(line, "{}") {
			continue
		}

		if strings.HasSuffix(line, "{") {
			blk := parseTFBlockHeader(line, lineNo)
			stack = append(stack, blk)
			continue
		}

		if line == "}" || strings.HasPrefix(line, "}") {
			if len(stack) > 0 {
				closed := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				var parent *tfBlock
				if len(stack) > 0 {
					parent = stack[len(stack)-1]
				}
				findings = append(findings, evaluateClosedTFBlock(closed, parent, target, now)...)
			}
			continue
		}

		if _, val, ok := parseTFAssignRaw(line); ok {
			d := netBracketDelta(val)
			if d > 0 {
				pending = line
				pendingStartLine = lineNo
				bracketDepth = d
			} else {
				flushAssign(line, lineNo)
			}
		}
	}

	return findings
}

func prepareTFLines(content string) []string {
	rawLines := strings.Split(content, "\n")
	out := make([]string, len(rawLines))
	inBlockComment := false

	for i, raw := range rawLines {
		var b strings.Builder
		var quote byte
		for j := 0; j < len(raw); j++ {
			ch := raw[j]
			if inBlockComment {
				if ch == '*' && j+1 < len(raw) && raw[j+1] == '/' {
					inBlockComment = false
					j++
				}
				continue
			}
			if quote != 0 {
				b.WriteByte(ch)
				if ch == '\\' && j+1 < len(raw) {
					j++
					b.WriteByte(raw[j])
					continue
				}
				if ch == quote {
					quote = 0
				}
				continue
			}
			if ch == '"' || ch == '\'' {
				quote = ch
				b.WriteByte(ch)
				continue
			}
			if ch == '#' {
				break
			}
			if ch == '/' && j+1 < len(raw) {
				if raw[j+1] == '/' {
					break
				}
				if raw[j+1] == '*' {
					inBlockComment = true
					j++
					continue
				}
			}
			b.WriteByte(ch)
		}
		out[i] = strings.TrimSpace(b.String())
	}
	return out
}

func collectTFBindings(lines []string) map[string]string {
	bindings := make(map[string]string)
	depth := 0
	var curVar string
	inLocals := false
	localsDepth := 0
	var pendingKey, pendingVal string
	bracketDepth := 0

	for _, line := range lines {
		if line == "" {
			continue
		}
		if pendingKey != "" {
			pendingVal += " " + line
			bracketDepth += netBracketDelta(line)
			if bracketDepth <= 0 {
				bindings[pendingKey] = strings.TrimSpace(pendingVal)
				pendingKey = ""
				pendingVal = ""
				bracketDepth = 0
			}
			continue
		}

		if curVar == "" && !inLocals {
			if m := tfVarHdrRe.FindStringSubmatch(line); len(m) >= 2 {
				curVar = strings.TrimSpace(m[1])
				depth = 1
				continue
			}
			if strings.HasPrefix(strings.ToLower(line), "locals") && strings.HasSuffix(line, "{") {
				inLocals = true
				localsDepth = 1
				continue
			}
		}

		if strings.HasSuffix(line, "{") {
			if curVar != "" {
				depth++
			}
			if inLocals {
				localsDepth++
			}
			continue
		}
		if line == "}" || strings.HasPrefix(line, "}") {
			if curVar != "" {
				depth--
				if depth <= 0 {
					curVar = ""
				}
			}
			if inLocals {
				localsDepth--
				if localsDepth <= 0 {
					inLocals = false
				}
			}
			continue
		}

		if curVar != "" && depth == 1 {
			if k, v, ok := parseTFAssignRaw(line); ok && strings.EqualFold(k, "default") {
				d := netBracketDelta(v)
				if d > 0 {
					pendingKey = "var." + curVar
					pendingVal = v
					bracketDepth = d
				} else {
					bindings["var."+curVar] = strings.TrimSpace(v)
				}
			}
		} else if inLocals && localsDepth == 1 {
			if k, v, ok := parseTFAssignRaw(line); ok {
				d := netBracketDelta(v)
				if d > 0 {
					pendingKey = "local." + k
					pendingVal = v
					bracketDepth = d
				} else {
					bindings["local."+k] = strings.TrimSpace(v)
				}
			}
		}
	}
	return bindings
}

func resolveTFExpr(expr string, bindings map[string]string) string {
	cur := expr
	for step := 0; step < 4; step++ {
		next := tfVarRefRe.ReplaceAllStringFunc(cur, func(match string) string {
			if v, ok := bindings[match]; ok && v != "" {
				return v
			}
			return match
		})
		if next == cur {
			break
		}
		cur = next
	}
	return cur
}

func parseTFBlockHeader(line string, lineNo int) *tfBlock {
	blk := &tfBlock{
		openLine: lineNo,
		attrs:    make(map[string]string),
	}
	if m := tfResourceHdrRe.FindStringSubmatch(line); len(m) >= 3 {
		blk.kind = "resource"
		blk.resType = strings.ToLower(m[1])
		blk.resName = m[2]
		return blk
	}
	head := strings.TrimSpace(strings.TrimSuffix(line, "{"))
	fields := strings.Fields(head)
	if len(fields) > 0 {
		blk.kind = strings.ToLower(strings.Trim(fields[0], `"'`))
	}
	return blk
}

func evaluateClosedTFBlock(closed, parent *tfBlock, target string, now time.Time) []schema.Finding {
	var findings []schema.Finding

	switch closed.kind {
	case "ingress":
		if hasOpenCIDR(closed.attrs["cidr_blocks"]) || hasOpenCIDR(closed.attrs["ipv6_cidr_blocks"]) {
			fromP, hasFrom := parseTFInt(closed.attrs["from_port"])
			toP, hasTo := parseTFInt(closed.attrs["to_port"])
			proto := strings.Trim(closed.attrs["protocol"], `"' `)
			if tfPortsExposeMgmt(fromP, toP, hasFrom, hasTo, proto) {
				findings = append(findings, schema.NewFinding(
					"PIPE-304", "iac", schema.SeverityHigh,
					"Terraform security group opens management ports (SSH/RDP/all) to 0.0.0.0/0",
					fmt.Sprintf("Ingress block starting on line %d exposes SSH/RDP or all ports to public Internet CIDR.", closed.openLine),
					target,
					map[string]any{"line": closed.openLine, "from_port": fromP, "to_port": toP, "standard": "CIS Cloud Benchmark"},
					"Restrict ingress CIDR blocks strictly to corporate VPN/bastion IPs or remove direct SSH/RDP exposure.",
					"D3-CH", fmt.Sprintf("tf-l%d-sg", closed.openLine), now,
				))
			}
		}

	case "allow":
		if parent != nil && parent.resType == "google_compute_firewall" {
			parent.allows = append(parent.allows, tfAllowRule{
				line:     closed.openLine,
				protocol: strings.Trim(closed.attrs["protocol"], `"' `),
				ports:    closed.attrs["ports"],
			})
		}

	case "security_rule":
		if parent != nil && parent.resType == "azurerm_network_security_group" {
			parent.secRules = append(parent.secRules, closed.attrs)
			if f, ok := auditAzureSecurityRule(closed.attrs, closed.openLine, target, now); ok {
				findings = append(findings, f)
			}
		}

	case "statement":
		if parent != nil && (parent.resType == "" || strings.HasPrefix(parent.resType, "aws_iam")) {
			parent.statements = append(parent.statements, tfStatement{
				line:      closed.openLine,
				effect:    strings.Trim(closed.attrs["effect"], `"' `),
				actions:   closed.attrs["actions"],
				resources: closed.attrs["resources"],
			})
		}

	case "authorized_networks":
		if hasOpenCIDR(closed.attrs["value"]) {
			findings = append(findings, schema.NewFinding(
				"PIPE-305", "iac", schema.SeverityHigh,
				"Terraform Cloud SQL instance allows public authorized_networks 0.0.0.0/0",
				fmt.Sprintf("Cloud SQL authorized_networks block on line %d authorizes public Internet access.", closed.openLine),
				target,
				map[string]any{"line": closed.openLine, "standard": "CIS GCP Benchmark"},
				"Use private VPC peering / Cloud SQL Auth Proxy and restrict authorized_networks strictly to trusted CIDRs.",
				"D3-CH", fmt.Sprintf("tf-gcp-sql-l%d", closed.openLine), now,
			))
		}

	case "resource":
		findings = append(findings, evaluateClosedTFResource(closed, target, now)...)
	}

	return findings
}

func evaluateClosedTFResource(res *tfBlock, target string, now time.Time) []schema.Finding {
	var findings []schema.Finding

	switch res.resType {
	case "aws_vpc_security_group_ingress_rule", "aws_security_group_rule":
		if res.resType == "aws_security_group_rule" {
			ruleType := strings.Trim(res.attrs["type"], `"' `)
			if ruleType != "" && ruleType != "ingress" {
				return nil
			}
		}
		if hasOpenCIDR(res.attrs["cidr_ipv4"]) || hasOpenCIDR(res.attrs["cidr_ipv6"]) || hasOpenCIDR(res.attrs["cidr_blocks"]) || hasOpenCIDR(res.attrs["ipv6_cidr_blocks"]) {
			fromP, hasFrom := parseTFInt(res.attrs["from_port"])
			toP, hasTo := parseTFInt(res.attrs["to_port"])
			proto := strings.Trim(res.attrs["ip_protocol"], `"' `)
			if proto == "" {
				proto = strings.Trim(res.attrs["protocol"], `"' `)
			}
			if tfPortsExposeMgmt(fromP, toP, hasFrom, hasTo, proto) {
				findings = append(findings, schema.NewFinding(
					"PIPE-304", "iac", schema.SeverityHigh,
					"Terraform AWS ingress rule opens management ports to 0.0.0.0/0",
					fmt.Sprintf("Resource %s.%s (line %d) exposes SSH/RDP or all ports publicly.", res.resType, res.resName, res.openLine),
					target,
					map[string]any{"line": res.openLine, "resource": res.resType, "standard": "CIS Cloud Benchmark"},
					"Restrict ingress CIDRs to corporate bastion/VPN ranges.",
					"D3-CH", fmt.Sprintf("tf-aws-rule-l%d", res.openLine), now,
				))
			}
		}

	case "google_compute_firewall":
		dir := strings.Trim(res.attrs["direction"], `"' `)
		if dir == "egress" {
			return nil
		}
		if hasOpenCIDR(res.attrs["source_ranges"]) {
			for _, al := range res.allows {
				if al.protocol == "all" || al.ports == "" || listCoversMgmtPorts(al.ports) {
					findings = append(findings, schema.NewFinding(
						"PIPE-305", "iac", schema.SeverityHigh,
						"Terraform GCP firewall rule exposes management ports to 0.0.0.0/0",
						fmt.Sprintf("google_compute_firewall.%s (line %d) allows public source_ranges access to sensitive ports/all traffic.", res.resName, res.openLine),
						target,
						map[string]any{"line": res.openLine, "resource": res.resName, "protocol": al.protocol, "standard": "CIS GCP Benchmark"},
						"Restrict source_ranges to Identity-Aware Proxy (35.235.240.0/20) or private VPC CIDRs.",
						"D3-CH", fmt.Sprintf("tf-gcp-fw-l%d", res.openLine), now,
					))
					break
				}
			}
		}

	case "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding":
		combined := res.attrs["member"] + " " + res.attrs["members"]
		if strings.Contains(combined, "allusers") || strings.Contains(combined, "allauthenticatedusers") {
			findings = append(findings, schema.NewFinding(
				"PIPE-305", "iac", schema.SeverityHigh,
				"Terraform GCP storage IAM grants public allUsers or allAuthenticatedUsers access",
				fmt.Sprintf("%s.%s (line %d) binds public principal to Cloud Storage bucket.", res.resType, res.resName, res.openLine),
				target,
				map[string]any{"line": res.openLine, "resource": res.resName, "standard": "CIS GCP Benchmark"},
				"Remove allUsers/allAuthenticatedUsers members and enforce public_access_prevention = \"enforced\".",
				"D3-CH", fmt.Sprintf("tf-gcp-gcs-l%d", res.openLine), now,
			))
		}

	case "azurerm_network_security_rule":
		if f, ok := auditAzureSecurityRule(res.attrs, res.openLine, target, now); ok {
			findings = append(findings, f)
		}

	case "azurerm_storage_account":
		pub := strings.Trim(res.attrs["allow_nested_items_to_be_public"], `"' `)
		legacyPub := strings.Trim(res.attrs["allow_blob_public_access"], `"' `)
		httpsLegacy := strings.Trim(res.attrs["enable_https_traffic_only"], `"' `)
		httpsModern := strings.Trim(res.attrs["https_traffic_only_enabled"], `"' `)
		if pub == "true" || legacyPub == "true" || httpsLegacy == "false" || httpsModern == "false" {
			findings = append(findings, schema.NewFinding(
				"PIPE-306", "iac", schema.SeverityHigh,
				"Terraform Azure storage account permits public blobs or disables HTTPS-only traffic",
				fmt.Sprintf("azurerm_storage_account.%s (line %d) weakens Azure storage public-access or HTTPS safeguards.", res.resName, res.openLine),
				target,
				map[string]any{"line": res.openLine, "resource": res.resName, "standard": "CIS Azure Benchmark"},
				"Set allow_nested_items_to_be_public = false and https_traffic_only_enabled = true.",
				"D3-CH", fmt.Sprintf("tf-az-stg-l%d", res.openLine), now,
			))
		}
	}

	for _, st := range res.statements {
		if st.effect != "deny" && containsWildcardToken(st.actions) && containsWildcardToken(st.resources) {
			findings = append(findings, schema.NewFinding(
				"PIPE-304", "iac", schema.SeverityHigh,
				"Terraform IAM policy statement grants wildcard '*' actions on '*' resources",
				fmt.Sprintf("Statement on line %d configures unrestricted wildcard permissions.", st.line),
				target,
				map[string]any{"line": st.line, "standard": "CIS Cloud Benchmark"},
				"Replace wildcard '*' actions and resources with least-privilege permissions.",
				"D3-CH", fmt.Sprintf("tf-iam-stmt-l%d", st.line), now,
			))
		}
	}

	return findings
}

func auditAzureSecurityRule(attrs map[string]string, line int, target string, now time.Time) (schema.Finding, bool) {
	access := strings.Trim(attrs["access"], `"' `)
	dir := strings.Trim(attrs["direction"], `"' `)
	if access != "allow" || dir != "inbound" {
		return schema.Finding{}, false
	}
	src := attrs["source_address_prefix"] + " " + attrs["source_address_prefixes"]
	if !isAzureOpenSource(src) {
		return schema.Finding{}, false
	}
	dst := attrs["destination_port_range"] + " " + attrs["destination_port_ranges"]
	if strings.Contains(dst, `"*"`) || strings.Trim(dst, `"' `) == "*" || listCoversMgmtPorts(dst) {
		return schema.NewFinding(
			"PIPE-306", "iac", schema.SeverityHigh,
			"Terraform Azure NSG rule exposes SSH/RDP or all ports to Internet",
			fmt.Sprintf("Azure NSG Allow/Inbound rule (line %d) permits public Internet ingress to sensitive management ports.", line),
			target,
			map[string]any{"line": line, "standard": "CIS Azure Benchmark"},
			"Restrict source_address_prefix to corporate VPN/bastion CIDRs and scope destination ports tightly.",
			"D3-CH", fmt.Sprintf("tf-az-nsg-l%d", line), now,
		), true
	}
	return schema.Finding{}, false
}

func isAzureOpenSource(src string) bool {
	if hasOpenCIDR(src) {
		return true
	}
	return strings.Contains(src, `"*"`) || strings.Contains(src, "internet") || strings.Contains(src, "any") || strings.Trim(src, `"' `) == "*"
}

func containsWildcardToken(expr string) bool {
	for _, m := range tfQuotedStrRe.FindAllStringSubmatch(expr, -1) {
		if len(m) >= 2 && strings.TrimSpace(m[1]) == "*" {
			return true
		}
	}
	return false
}

func hasOpenCIDR(expr string) bool {
	return strings.Contains(expr, "0.0.0.0/0") || strings.Contains(expr, "::/0")
}

func listCoversMgmtPorts(expr string) bool {
	if strings.Trim(expr, `"' `) == "*" || strings.Contains(expr, `"*"`) {
		return true
	}
	for _, m := range tfQuotedStrRe.FindAllStringSubmatch(expr, -1) {
		if len(m) < 2 {
			continue
		}
		tok := strings.TrimSpace(m[1])
		if tok == "22" || tok == "3389" || tok == "*" {
			return true
		}
		if dash := strings.IndexByte(tok, '-'); dash > 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(tok[:dash]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(tok[dash+1:]))
			if err1 == nil && err2 == nil && ((lo <= 22 && hi >= 22) || (lo <= 3389 && hi >= 3389)) {
				return true
			}
		}
	}
	for _, m := range tfIntTokenRe.FindAllStringSubmatch(expr, -1) {
		if len(m) >= 2 && (m[1] == "22" || m[1] == "3389") {
			return true
		}
	}
	return false
}

func tfPortsExposeMgmt(fromP, toP int, hasFrom, hasTo bool, proto string) bool {
	if proto == "-1" || strings.EqualFold(proto, "all") {
		return true
	}
	if !hasFrom && !hasTo {
		return false
	}
	lo, hi := fromP, toP
	if !hasTo {
		hi = lo
	}
	if !hasFrom {
		lo = hi
	}
	if lo == 0 && hi == 0 {
		return true
	}
	return (lo <= 22 && hi >= 22) || (lo <= 3389 && hi >= 3389)
}

func parseTFAssignRaw(line string) (key, val string, ok bool) {
	var quote byte
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(line) {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quote = ch
			continue
		}
		if ch == '=' {
			if i+1 < len(line) && line[i+1] == '=' {
				i++
				continue
			}
			lhs := strings.TrimSpace(line[:i])
			if lhs == "" || strings.ContainsAny(lhs, " \t{}") {
				return "", "", false
			}
			return lhs, strings.TrimSpace(line[i+1:]), true
		}
	}
	return "", "", false
}

func parseTFInt(expr string) (int, bool) {
	clean := strings.Trim(strings.TrimSpace(expr), `"' `)
	n, err := strconv.Atoi(clean)
	if err != nil {
		return 0, false
	}
	return n, true
}

func netBracketDelta(s string) int {
	delta := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'':
			quote = ch
		case '[', '(':
			delta++
		case ']', ')':
			delta--
		}
	}
	return delta
}
