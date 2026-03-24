package domainutil

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func NormalizeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

func Labels(name string) []string {
	name = NormalizeName(name)
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

func ParentDomains(name string, maxLevels int) []string {
	parts := Labels(name)
	if len(parts) < 3 || maxLevels <= 0 {
		return nil
	}

	limit := len(parts) - 2
	if maxLevels < limit {
		limit = maxLevels
	}

	parents := make([]string, 0, limit)
	for i := 1; i <= limit; i++ {
		parents = append(parents, strings.Join(parts[i:], "."))
	}
	return parents
}

func ImmediateParent(name string) (string, bool) {
	parents := ParentDomains(name, 1)
	if len(parents) == 0 {
		return "", false
	}
	return parents[0], true
}

func ZoneCandidates(name string, maxParentWalk int) []string {
	name = NormalizeName(name)
	if name == "" {
		return nil
	}
	labels := Labels(name)
	if len(labels) == 0 {
		return nil
	}
	out := []string{name}
	parents := ParentDomains(name, maxParentWalk)
	out = append(out, parents...)
	return out
}

func Apex(name string) string {
	name = NormalizeName(name)
	if name == "" {
		return ""
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return NormalizeName(apex)
}

func MatchSuffix(name, suffix string) bool {
	name = NormalizeName(name)
	suffix = NormalizeName(suffix)
	if name == "" || suffix == "" {
		return false
	}
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

func LabelBeforeSuffix(name, suffix string) (string, error) {
	name = NormalizeName(name)
	suffix = NormalizeName(suffix)
	if name == "" || suffix == "" {
		return "", fmt.Errorf("name and suffix must be set")
	}
	if !MatchSuffix(name, suffix) {
		return "", fmt.Errorf("%q does not end in %q", name, suffix)
	}

	nameLabels := Labels(name)
	suffixLabels := Labels(suffix)
	if len(nameLabels) <= len(suffixLabels) {
		return "", fmt.Errorf("%q has no label before %q", name, suffix)
	}
	return nameLabels[len(nameLabels)-len(suffixLabels)-1], nil
}
