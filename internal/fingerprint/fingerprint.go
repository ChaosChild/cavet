// Package fingerprint owns finding identity: rule keys, context normalisation,
// and hashing (SPECIFICATION.md §3.3, artefacts-spec.md §5).
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const ContextLines = 3

var (
	reStrings = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`" + `[^` + "`" + `]*` + "`")
	reNumbers = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	reWS      = regexp.MustCompile(`\s+`)
)

// RuleKey prefers the CWE mapping; scanner rule ids are the fallback (spec §3.3).
func RuleKey(cwe, ruleID string) string {
	if cwe != "" {
		return cwe
	}
	return ruleID
}

// Of returns the finding fingerprint: sha256(rule_key + \x00 + normalised context).
func Of(ruleKey, normalisedContext string) string {
	h := sha256.Sum256([]byte(ruleKey + "\x00" + normalisedContext))
	return hex.EncodeToString(h[:])
}

// Secret returns the pre-collapse identity for secret findings:
// sha256(matched span + \x00 + repo-relative path). Never persisted (artefacts §5).
func Secret(matchedSpan, repoPath string) string {
	h := sha256.Sum256([]byte(matchedSpan + "\x00" + repoPath))
	return hex.EncodeToString(h[:])
}

// Normalise produces the stable context string fingerprinted by Of: the match line
// plus ContextLines either side, string and numeric literals masked, whitespace
// collapsed (artefacts §5, steps 1-6).
//
// ponytail: no NFC normalisation — stdlib-only; add x/text between decode and CRLF
// fold only if real-world misses show up (artefacts §5).
func Normalise(src []byte, matchLine int) (string, error) {
	if matchLine < 1 {
		return "", fmt.Errorf("matchLine must be >= 1, got %d", matchLine)
	}
	s := strings.ToValidUTF8(string(src), "\uFFFD")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	start := matchLine - 1 - ContextLines
	if start < 0 {
		start = 0
	}
	end := matchLine - 1 + ContextLines
	if end > len(lines)-1 {
		end = len(lines) - 1
	}
	ctx := strings.Join(lines[start:end+1], "\n")
	ctx = reStrings.ReplaceAllString(ctx, "«s»")
	ctx = reNumbers.ReplaceAllString(ctx, "«n»")
	ctx = reWS.ReplaceAllString(ctx, " ")
	return strings.TrimSpace(ctx), nil
}
