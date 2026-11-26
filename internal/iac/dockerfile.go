package iac

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/luminariadev/raksa-pipeguard/internal/schema"
)

type dockerInstruction struct {
	lineNo int
	cmd    string
	args   string
}

type dockerStage struct {
	lineNo         int
	image          string
	alias          string
	hasUser        bool
	userLine       int
	userVal        string
	hasExpose      bool
	hasHealthcheck bool
}

var (
	curlPipeShellRe = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|\r\n]*\|\s*(?:sh|bash|ash|dash|zsh)\b`)
	insecureTLSRe   = regexp.MustCompile(`(?i)(?:\bcurl\b[^|\r\n]*(?:\s-k(?:\s|$)|--insecure\b)|\bwget\b[^|\r\n]*--no-check-certificate\b)`)
	addRemoteHTTPRe = regexp.MustCompile(`(?i)^https?://`)
	sudoOrChmodRe   = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)\bsudo\b|chmod\s+(?:-R\s+)?(?:0?777|[ugo]*\+s)`)
	dockerVarBraced = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)
	dockerVarBare   = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
)

func LintDockerfile(content string, target string) []schema.Finding {
	insts := parseDockerInstructions(content)
	if len(insts) == 0 {
		return nil
	}

	now := time.Now().UTC()
	var (
		findings   []schema.Finding
		stages     []dockerStage
		aliases    = make(map[string]bool)
		globalArgs = make(map[string]string)
		stageArgs  = make(map[string]string)
	)

	var curStage *dockerStage

	for _, inst := range insts {
		switch inst.cmd {
		case "FROM":
			rawImg, alias := parseFromArgs(inst.args)
			img := resolveDockerVars(rawImg, globalArgs)
			st := dockerStage{
				lineNo: inst.lineNo,
				image:  img,
				alias:  alias,
			}
			stages = append(stages, st)
			curStage = &stages[len(stages)-1]
			stageArgs = make(map[string]string)
			for k, v := range globalArgs {
				stageArgs[k] = v
			}

			imgLow := strings.ToLower(img)
			if imgLow != "scratch" && !aliases[imgLow] {
				if isUnpinnedDockerImage(imgLow) {
					findings = append(findings, schema.NewFinding(
						"PIPE-202", "iac", schema.SeverityMedium,
						"Dockerfile base image uses mutable :latest or unpinned tag",
						fmt.Sprintf("FROM %s on line %d omits an immutable version tag or SHA-256 digest.", img, inst.lineNo),
						target,
						map[string]any{"line": inst.lineNo, "image": img, "standard": "CIS Docker 4.7"},
						"Pin base images to an explicit version tag (e.g. golang:1.26-alpine) or @sha256: digest.",
						"D3-CH", fmt.Sprintf("docker-l%d-from", inst.lineNo), now,
					))
				}
			}
			if alias != "" {
				aliases[strings.ToLower(alias)] = true
			}

		case "USER":
			if curStage != nil {
				fields := strings.Fields(inst.args)
				if len(fields) > 0 {
					userVal := strings.TrimSpace(fields[0])
					curStage.hasUser = true
					curStage.userLine = inst.lineNo
					curStage.userVal = strings.ToLower(userVal)
				}
			}

		case "EXPOSE":
			if curStage != nil {
				curStage.hasExpose = true
			}
			for _, portTok := range strings.Fields(inst.args) {
				p := strings.ToLower(strings.TrimSpace(portTok))
				if p == "22" || strings.HasPrefix(p, "22/") {
					findings = append(findings, schema.NewFinding(
						"PIPE-206", "iac", schema.SeverityMedium,
						"Dockerfile exposes SSH port 22",
						fmt.Sprintf("EXPOSE %s on line %d opens SSH inside the container image.", portTok, inst.lineNo),
						target,
						map[string]any{"line": inst.lineNo, "port": portTok, "standard": "CIS Docker 4.6"},
						"Remove SSH daemons and EXPOSE 22; manage containers via orchestrator exec rather than SSH.",
						"D3-CH", fmt.Sprintf("docker-l%d-ssh", inst.lineNo), now,
					))
				}
			}

		case "HEALTHCHECK":
			if curStage != nil && !strings.EqualFold(strings.TrimSpace(inst.args), "NONE") {
				curStage.hasHealthcheck = true
			}

		case "ENV", "ARG":
			if curStage == nil && inst.cmd == "ARG" {
				recordDockerKeyVals(inst.args, globalArgs)
			} else {
				recordDockerKeyVals(inst.args, stageArgs)
			}
			if k, ok := findHardcodedSecretEnvArg(inst.args); ok {
				findings = append(findings, schema.NewFinding(
					"PIPE-203", "iac", schema.SeverityHigh,
					"Dockerfile embeds sensitive secret in ENV or ARG",
					fmt.Sprintf("%s %s on line %d hardcodes a credential value inside image layer metadata.", inst.cmd, k, inst.lineNo),
					target,
					map[string]any{"line": inst.lineNo, "instruction": inst.cmd, "key": k, "standard": "CIS Docker 4.10"},
					"Pass secrets via BuildKit secret mounts (--mount=type=secret) or runtime secret injection instead of ENV/ARG.",
					"D3-KM", fmt.Sprintf("docker-l%d-secret", inst.lineNo), now,
				))
			}

		case "RUN":
			if curlPipeShellRe.MatchString(inst.args) {
				findings = append(findings, schema.NewFinding(
					"PIPE-204", "iac", schema.SeverityHigh,
					"Dockerfile pipes remote script directly into shell",
					fmt.Sprintf("RUN instruction on line %d executes remote content via curl/wget pipe to shell.", inst.lineNo),
					target,
					map[string]any{"line": inst.lineNo, "standard": "OWASP CI/CD-SEC-4"},
					"Download verified artifacts with SHA-256 checksum checks before executing them.",
					"D3-CH", fmt.Sprintf("docker-l%d-pipe-sh", inst.lineNo), now,
				))
			}
			if insecureTLSRe.MatchString(inst.args) {
				findings = append(findings, schema.NewFinding(
					"PIPE-204", "iac", schema.SeverityHigh,
					"Dockerfile disables TLS certificate verification during download",
					fmt.Sprintf("RUN instruction on line %d passes insecure TLS bypass flags (-k/--insecure/--no-check-certificate).", inst.lineNo),
					target,
					map[string]any{"line": inst.lineNo, "standard": "OWASP CI/CD-SEC-4"},
					"Remove TLS verification bypass flags and verify artifact checksums.",
					"D3-CH", fmt.Sprintf("docker-l%d-tls-bypass", inst.lineNo), now,
				))
			}
			if sudoOrChmodRe.MatchString(inst.args) {
				findings = append(findings, schema.NewFinding(
					"PIPE-205", "iac", schema.SeverityMedium,
					"Dockerfile weakens privilege boundaries via sudo, 777, or setuid",
					fmt.Sprintf("RUN instruction on line %d invokes sudo, chmod 777, or setuid bits.", inst.lineNo),
					target,
					map[string]any{"line": inst.lineNo, "standard": "CIS Docker 4.8"},
					"Use least-privilege file permissions (e.g. 0755/0644) and avoid sudo or setuid binaries.",
					"D3-CH", fmt.Sprintf("docker-l%d-perms", inst.lineNo), now,
				))
			}

		case "ADD":
			fields := strings.Fields(inst.args)
			if len(fields) >= 2 && addRemoteHTTPRe.MatchString(fields[0]) {
				findings = append(findings, schema.NewFinding(
					"PIPE-204", "iac", schema.SeverityHigh,
					"Dockerfile fetches unverified remote asset using ADD URL",
					fmt.Sprintf("ADD %s on line %d downloads remote content without cryptographic verification.", fields[0], inst.lineNo),
					target,
					map[string]any{"line": inst.lineNo, "source": fields[0], "standard": "OWASP CI/CD-SEC-4"},
					"Prefer COPY from local verified build context or curl + sha256sum verification.",
					"D3-CH", fmt.Sprintf("docker-l%d-add-url", inst.lineNo), now,
				))
			}
		}
	}

	if len(stages) > 0 {
		final := stages[len(stages)-1]
		isNonRootTag := strings.Contains(strings.ToLower(final.image), "nonroot")
		isExplicitRoot := final.hasUser && (final.userVal == "root" || final.userVal == "0" || strings.HasPrefix(final.userVal, "0:") || strings.HasPrefix(final.userVal, "root:"))

		if isExplicitRoot || (!final.hasUser && !isNonRootTag) {
			line := final.lineNo
			if isExplicitRoot && final.userLine > 0 {
				line = final.userLine
			}
			findings = append(findings, schema.NewFinding(
				"PIPE-201", "iac", schema.SeverityHigh,
				"Dockerfile runs final stage as root user",
				fmt.Sprintf("Final container stage (%s) runs as root (line %d).", final.image, line),
				target,
				map[string]any{"line": line, "image": final.image, "standard": "CIS Docker 4.1"},
				"Create a dedicated non-root USER (or use a :nonroot distroless base image and set USER nonroot:nonroot).",
				"D3-CH", fmt.Sprintf("docker-l%d-root", line), now,
			))
		}

		if final.hasExpose && !final.hasHealthcheck {
			findings = append(findings, schema.NewFinding(
				"PIPE-206", "iac", schema.SeverityLow,
				"Dockerfile exposes network port without HEALTHCHECK instruction",
				fmt.Sprintf("Final stage starting on line %d declares EXPOSE without a HEALTHCHECK probe.", final.lineNo),
				target,
				map[string]any{"line": final.lineNo, "standard": "CIS Docker 4.6"},
				"Add a HEALTHCHECK instruction to verify container liveness.",
				"D3-CH", fmt.Sprintf("docker-l%d-healthcheck", final.lineNo), now,
			))
		}
	}

	return findings
}

func parseDockerInstructions(content string) []dockerInstruction {
	lines := strings.Split(content, "\n")
	var out []dockerInstruction

	var buf strings.Builder
	startLine := 0

	for idx, rawLine := range lines {
		lineNo := idx + 1
		trimmed := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
		if startLine == 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			startLine = lineNo
		} else if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasSuffix(trimmed, `\`) {
			buf.WriteString(strings.TrimSpace(strings.TrimSuffix(trimmed, `\`)))
			buf.WriteByte(' ')
			continue
		}

		buf.WriteString(trimmed)
		full := strings.TrimSpace(buf.String())
		buf.Reset()

		fields := strings.Fields(full)
		if len(fields) > 0 {
			cmd := strings.ToUpper(fields[0])
			args := strings.TrimSpace(strings.TrimPrefix(full, fields[0]))
			out = append(out, dockerInstruction{lineNo: startLine, cmd: cmd, args: args})
		}
		startLine = 0
	}

	if buf.Len() > 0 {
		full := strings.TrimSpace(buf.String())
		fields := strings.Fields(full)
		if len(fields) > 0 {
			cmd := strings.ToUpper(fields[0])
			args := strings.TrimSpace(strings.TrimPrefix(full, fields[0]))
			out = append(out, dockerInstruction{lineNo: startLine, cmd: cmd, args: args})
		}
	}
	return out
}

func parseFromArgs(args string) (image, alias string) {
	fields := strings.Fields(args)
	var positional []string
	for _, f := range fields {
		if strings.HasPrefix(f, "--") {
			continue
		}
		positional = append(positional, f)
	}
	if len(positional) >= 1 {
		image = positional[0]
	}
	if len(positional) >= 3 && strings.EqualFold(positional[1], "AS") {
		alias = positional[2]
	}
	return image, alias
}

func isUnpinnedDockerImage(imgLow string) bool {
	if strings.Contains(imgLow, "@sha256:") {
		return false
	}
	lastSlash := strings.LastIndexByte(imgLow, '/')
	tail := imgLow
	if lastSlash >= 0 {
		tail = imgLow[lastSlash+1:]
	}
	colon := strings.IndexByte(tail, ':')
	if colon < 0 {
		return true
	}
	tag := tail[colon+1:]
	return tag == "" || tag == "latest"
}

func findHardcodedSecretEnvArg(args string) (string, bool) {
	for _, tok := range strings.Fields(args) {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(tok[:eq])
		val := strings.Trim(strings.TrimSpace(tok[eq+1:]), `"'`)
		if val == "" || strings.HasPrefix(val, "$") || strings.Contains(strings.ToLower(val), "example") || strings.Contains(strings.ToLower(val), "placeholder") {
			continue
		}
		kUp := strings.ToUpper(key)
		for _, bad := range []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY", "PRIVATE_KEY"} {
			if strings.Contains(kUp, bad) {
				return key, true
			}
		}
	}
	return "", false
}

func recordDockerKeyVals(args string, dest map[string]string) {
	fields := strings.Fields(args)
	if len(fields) >= 2 && !strings.Contains(fields[0], "=") {
		val := strings.Trim(strings.Join(fields[1:], " "), `"'`)
		dest[strings.TrimSpace(fields[0])] = val
		return
	}
	for _, tok := range fields {
		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(tok[:eq])
		v := strings.Trim(strings.TrimSpace(tok[eq+1:]), `"'`)
		dest[k] = v
	}
}

func resolveDockerVars(raw string, vars map[string]string) string {
	out := dockerVarBraced.ReplaceAllStringFunc(raw, func(match string) string {
		sub := dockerVarBraced.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		if v := strings.TrimSpace(vars[sub[1]]); v != "" {
			return v
		}
		if len(sub) >= 3 && sub[2] != "" {
			return sub[2]
		}
		return ""
	})
	out = dockerVarBare.ReplaceAllStringFunc(out, func(match string) string {
		sub := dockerVarBare.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		if v, ok := vars[sub[1]]; ok {
			return strings.TrimSpace(v)
		}
		return ""
	})
	return out
}
