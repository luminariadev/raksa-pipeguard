package secrets

import (
	"math"
	"strings"
)

func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func MaskSecret(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) <= 6 {
		return "****"
	}
	if len(s) <= 10 {
		return s[:2] + "****" + s[len(s)-2:]
	}
	return s[:4] + "***REDACTED***" + s[len(s)-4:]
}

func IsPlaceholderSecret(val string) bool {
	trimmed := strings.TrimSpace(strings.Trim(val, `"'`))
	if len(trimmed) < 8 {
		return true
	}
	if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") {
		return true
	}
	if strings.HasPrefix(trimmed, "${") || strings.HasPrefix(trimmed, "$") || strings.HasPrefix(trimmed, "{{") {
		return true
	}

	low := strings.ToLower(trimmed)
	for _, marker := range []string{
		"example", "placeholder", "redacted", "changeme", "change_me",
		"your_", "your-", "sample", "dummy", "fake_", "mock_",
		"localhost", "127.0.0.1", "iosfodnn7", "insert_",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}

	if allSameOrSequential(trimmed) {
		return true
	}
	return false
}

func allSameOrSequential(s string) bool {
	if len(s) == 0 {
		return true
	}
	first := s[0]
	allSame := true
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			allSame = false
			break
		}
	}
	return allSame
}
