package providers

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"danglr/internal/domainutil"
	templateutil "danglr/internal/template"
)

const (
	ClassStrongSignal   = "strong-signal"
	ClassLegacyDangling = "legacy-dangling"
	ClassHeuristic      = "heuristic"

	DetectionModeTXTProtection      = "txt-protection"
	DetectionModeClaimableTarget    = "claimable-target"
	DetectionModePlatformHeuristic  = "platform-heuristic"
	DetectionModeOrphanedDelegation = "orphaned-delegation"

	ExtractionNone              = "none"
	ExtractionLabelBeforeSuffix = "label_before_suffix"
	ExtractionRegexCapture      = "regex_capture"

	VerificationTXTExists             = "txt_exists"
	VerificationTXTValueRegex         = "txt_value_regex"
	VerificationTXTExistsOrValueRegex = "txt_exists_or_value_regex"

	DanglingDNSTargetPatternOnly       = "dns-target-pattern-only"
	DanglingDNSTargetPlusWeakIndicator = "dns-target-plus-weak-indicator"

	HeuristicProviderTargetOnly = "provider-target-only"

	DelegationParentWithMissingZone = "parent-delegation-with-missing-zone"
)

var (
	validClasses             = []string{ClassStrongSignal, ClassLegacyDangling, ClassHeuristic}
	validDetectionModes      = []string{DetectionModeTXTProtection, DetectionModeClaimableTarget, DetectionModePlatformHeuristic, DetectionModeOrphanedDelegation}
	validExtractionTypes     = []string{ExtractionNone, ExtractionLabelBeforeSuffix, ExtractionRegexCapture}
	validVerificationMethods = []string{VerificationTXTExists, VerificationTXTValueRegex, VerificationTXTExistsOrValueRegex}
	validDanglingMethods     = []string{DanglingDNSTargetPatternOnly, DanglingDNSTargetPlusWeakIndicator}
	validHeuristicMethods    = []string{HeuristicProviderTargetOnly}
	validDelegationMethods   = []string{DelegationParentWithMissingZone}
	validConfidence          = []string{"low", "medium", "high"}
)

type Root struct {
	Providers []ProviderRule `yaml:"providers"`
}

type ProviderRule struct {
	Name                     string            `yaml:"name"`
	Enabled                  bool              `yaml:"enabled"`
	Class                    string            `yaml:"class"`
	DetectionMode            string            `yaml:"detection_mode"`
	Confidence               string            `yaml:"confidence"`
	Severity                 string            `yaml:"severity"`
	ManualValidationRequired bool              `yaml:"manual_validation_required"`
	Tags                     []string          `yaml:"tags"`
	Match                    MatchRule         `yaml:"match"`
	Extraction               ExtractionRule    `yaml:"extraction"`
	Verification             *VerificationRule `yaml:"verification,omitempty"`
	Dangling                 *DanglingRule     `yaml:"dangling,omitempty"`
	Heuristic                *HeuristicRule    `yaml:"heuristic,omitempty"`
	Delegation               *DelegationRule   `yaml:"delegation,omitempty"`
	Notes                    string            `yaml:"notes"`

	compiledTargetRegexes []*regexp.Regexp
	compiledValueRegexes  []*regexp.Regexp
	compiledExtractRegex  *regexp.Regexp
}

type MatchRule struct {
	DNSRecord           string   `yaml:"dns_record"`
	TargetSuffixes      []string `yaml:"target_suffixes"`
	TargetSuffixRegexes []string `yaml:"target_suffix_regexes"`
	NSSuffixes          []string `yaml:"ns_suffixes"`
	NSRegexes           []string `yaml:"ns_regexes"`
}

type ExtractionRule struct {
	Type         string `yaml:"type"`
	Suffix       string `yaml:"suffix,omitempty"`
	Regex        string `yaml:"regex,omitempty"`
	CaptureGroup int    `yaml:"capture_group,omitempty"`
}

type VerificationRule struct {
	Method                  string          `yaml:"method"`
	TXTTemplates            []string        `yaml:"txt_templates"`
	Inheritance             InheritanceRule `yaml:"inheritance"`
	ProtectedIfAnyTXTExists bool            `yaml:"protected_if_any_txt_exists"`
	TXTValueRegexes         []string        `yaml:"txt_value_regexes,omitempty"`
}

type InheritanceRule struct {
	Enabled         bool `yaml:"enabled"`
	MaxParentLevels int  `yaml:"max_parent_levels"`
}

type DanglingRule struct {
	Method     string `yaml:"method"`
	ClassifyAs string `yaml:"classify_as"`
}

type HeuristicRule struct {
	Method     string `yaml:"method"`
	ClassifyAs string `yaml:"classify_as"`
}

type DelegationRule struct {
	Method                    string   `yaml:"method"`
	ClassifyAs                string   `yaml:"classify_as"`
	RequireParentNSDelegation bool     `yaml:"require_parent_ns_delegation"`
	RequireAuthoritativeSOA   bool     `yaml:"require_authoritative_soa"`
	AuthoritativeRCodes       []string `yaml:"authoritative_rcodes"`
	DirectNSValidation        bool     `yaml:"direct_ns_validation"`
	MaxParentWalk             int      `yaml:"max_parent_walk"`
}

type MatchContext struct {
	Host        string
	FinalTarget string
	CNAMEChain  []string
}

type VerificationContext struct {
	Host              string
	ParentDomains     []string
	Apex              string
	Owner             string
	FinalTarget       string
	LabelBeforeSuffix string
}

type ProviderDecision struct {
	Provider                 string
	Class                    string
	DetectionMode            string
	Matched                  bool
	Protected                bool
	Unprotected              bool
	DetectionReason          string
	ProtectionReason         string
	CheckedTXTNames          []string
	TXTHits                  []string
	FindingType              string
	Evidence                 []string
	Confidence               string
	Severity                 string
	Tags                     []string
	ManualValidationRequired bool
	Owner                    string
	MatchedTarget            string
}

func (r *Root) Validate() error {
	if len(r.Providers) == 0 {
		return fmt.Errorf("providers list is empty")
	}
	seen := make(map[string]struct{}, len(r.Providers))
	for i := range r.Providers {
		if err := r.Providers[i].Validate(); err != nil {
			return fmt.Errorf("provider %d: %w", i, err)
		}
		if _, ok := seen[r.Providers[i].Name]; ok {
			return fmt.Errorf("duplicate provider name %q", r.Providers[i].Name)
		}
		seen[r.Providers[i].Name] = struct{}{}
	}
	return nil
}

func (p *ProviderRule) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return fmt.Errorf("missing provider name")
	}
	p.Class = strings.ToLower(strings.TrimSpace(p.Class))
	p.DetectionMode = strings.ToLower(strings.TrimSpace(p.DetectionMode))
	p.Confidence = strings.ToLower(strings.TrimSpace(p.Confidence))
	p.Extraction.Type = strings.ToLower(strings.TrimSpace(p.Extraction.Type))
	p.Match.DNSRecord = strings.ToLower(strings.TrimSpace(p.Match.DNSRecord))
	if !slices.Contains(validClasses, p.Class) {
		return fmt.Errorf("unsupported class %q", p.Class)
	}
	if !slices.Contains(validDetectionModes, p.DetectionMode) {
		return fmt.Errorf("unsupported detection_mode %q", p.DetectionMode)
	}
	if p.Confidence != "" && !slices.Contains(validConfidence, p.Confidence) {
		return fmt.Errorf("invalid confidence %q", p.Confidence)
	}
	if p.Match.DNSRecord == "" {
		p.Match.DNSRecord = "cname"
	}
	if p.Match.DNSRecord != "cname" && p.Match.DNSRecord != "ns" {
		return fmt.Errorf("unsupported dns_record %q", p.Match.DNSRecord)
	}
	switch p.Match.DNSRecord {
	case "cname":
		if len(p.Match.TargetSuffixes) == 0 && len(p.Match.TargetSuffixRegexes) == 0 {
			return fmt.Errorf("empty target matchers")
		}
		for i, suffix := range p.Match.TargetSuffixes {
			p.Match.TargetSuffixes[i] = domainutil.NormalizeName(suffix)
		}
		p.compiledTargetRegexes = nil
		for _, expr := range p.Match.TargetSuffixRegexes {
			re, err := regexp.Compile(expr)
			if err != nil {
				return fmt.Errorf("invalid target suffix regex %q: %w", expr, err)
			}
			p.compiledTargetRegexes = append(p.compiledTargetRegexes, re)
		}
	case "ns":
		if len(p.Match.NSSuffixes) == 0 && len(p.Match.NSRegexes) == 0 {
			return fmt.Errorf("empty ns matchers")
		}
		for i, suffix := range p.Match.NSSuffixes {
			p.Match.NSSuffixes[i] = domainutil.NormalizeName(suffix)
		}
		p.compiledTargetRegexes = nil
		for _, expr := range p.Match.NSRegexes {
			re, err := regexp.Compile(expr)
			if err != nil {
				return fmt.Errorf("invalid ns regex %q: %w", expr, err)
			}
			p.compiledTargetRegexes = append(p.compiledTargetRegexes, re)
		}
	}

	if p.Extraction.Type == "" {
		p.Extraction.Type = ExtractionNone
	}
	if !slices.Contains(validExtractionTypes, p.Extraction.Type) {
		return fmt.Errorf("unsupported extraction type %q", p.Extraction.Type)
	}
	switch p.Extraction.Type {
	case ExtractionLabelBeforeSuffix:
		p.Extraction.Suffix = domainutil.NormalizeName(p.Extraction.Suffix)
		if p.Extraction.Suffix == "" {
			return fmt.Errorf("label_before_suffix extraction requires suffix")
		}
	case ExtractionRegexCapture:
		re, err := regexp.Compile(p.Extraction.Regex)
		if err != nil {
			return fmt.Errorf("invalid extraction regex %q: %w", p.Extraction.Regex, err)
		}
		p.compiledExtractRegex = re
		if p.Extraction.CaptureGroup <= 0 {
			p.Extraction.CaptureGroup = 1
		}
	}

	switch p.DetectionMode {
	case DetectionModeTXTProtection:
		if p.Verification == nil {
			return fmt.Errorf("txt-protection provider requires verification block")
		}
		if err := p.Verification.validate(); err != nil {
			return err
		}
		if err := validateTemplateRequirements(*p); err != nil {
			return err
		}
		p.compiledValueRegexes = nil
		for _, expr := range p.Verification.TXTValueRegexes {
			re, err := regexp.Compile(expr)
			if err != nil {
				return fmt.Errorf("invalid txt value regex %q: %w", expr, err)
			}
			p.compiledValueRegexes = append(p.compiledValueRegexes, re)
		}
		if p.Dangling != nil || p.Heuristic != nil {
			return fmt.Errorf("txt-protection provider cannot define dangling or heuristic blocks")
		}
	case DetectionModeClaimableTarget:
		if p.Dangling == nil {
			return fmt.Errorf("claimable-target provider requires dangling block")
		}
		if p.Verification != nil {
			return fmt.Errorf("claimable-target provider cannot define verification block")
		}
		if p.Heuristic != nil {
			return fmt.Errorf("claimable-target provider cannot define heuristic block")
		}
		if !slices.Contains(validDanglingMethods, strings.ToLower(strings.TrimSpace(p.Dangling.Method))) {
			return fmt.Errorf("unsupported dangling method %q", p.Dangling.Method)
		}
		if strings.TrimSpace(p.Dangling.ClassifyAs) == "" {
			return fmt.Errorf("dangling classify_as is required")
		}
	case DetectionModePlatformHeuristic:
		if p.Heuristic == nil {
			return fmt.Errorf("platform-heuristic provider requires heuristic block")
		}
		if p.Verification != nil {
			return fmt.Errorf("platform-heuristic provider cannot define verification block")
		}
		if p.Dangling != nil {
			return fmt.Errorf("platform-heuristic provider cannot define dangling block")
		}
		if !slices.Contains(validHeuristicMethods, strings.ToLower(strings.TrimSpace(p.Heuristic.Method))) {
			return fmt.Errorf("unsupported heuristic method %q", p.Heuristic.Method)
		}
		if strings.TrimSpace(p.Heuristic.ClassifyAs) == "" {
			return fmt.Errorf("heuristic classify_as is required")
		}
	case DetectionModeOrphanedDelegation:
		if p.Match.DNSRecord != "ns" {
			return fmt.Errorf("orphaned-delegation providers must use dns_record ns")
		}
		if p.Delegation == nil {
			return fmt.Errorf("orphaned-delegation provider requires delegation block")
		}
		if p.Verification != nil || p.Dangling != nil || p.Heuristic != nil {
			return fmt.Errorf("orphaned-delegation provider cannot define verification, dangling, or heuristic blocks")
		}
		if !slices.Contains(validDelegationMethods, strings.ToLower(strings.TrimSpace(p.Delegation.Method))) {
			return fmt.Errorf("unsupported delegation method %q", p.Delegation.Method)
		}
		if strings.TrimSpace(p.Delegation.ClassifyAs) == "" {
			return fmt.Errorf("delegation classify_as is required")
		}
		if p.Delegation.MaxParentWalk < 0 {
			return fmt.Errorf("delegation max_parent_walk cannot be negative")
		}
		for i, rcode := range p.Delegation.AuthoritativeRCodes {
			p.Delegation.AuthoritativeRCodes[i] = strings.ToLower(strings.TrimSpace(rcode))
		}
	}

	return nil
}

func (v *VerificationRule) validate() error {
	v.Method = strings.ToLower(strings.TrimSpace(v.Method))
	if !slices.Contains(validVerificationMethods, v.Method) {
		return fmt.Errorf("unsupported verification method %q", v.Method)
	}
	if len(v.TXTTemplates) == 0 {
		return fmt.Errorf("verification requires at least one txt template")
	}
	for _, tmpl := range v.TXTTemplates {
		if err := templateutil.Validate(tmpl); err != nil {
			return fmt.Errorf("invalid txt template %q: %w", tmpl, err)
		}
	}
	if v.Inheritance.MaxParentLevels < 0 {
		return fmt.Errorf("inheritance max_parent_levels cannot be negative")
	}
	if !v.Inheritance.Enabled && v.Inheritance.MaxParentLevels > 0 {
		return fmt.Errorf("inheritance max_parent_levels cannot be > 0 when inheritance is disabled")
	}
	if (v.Method == VerificationTXTValueRegex || v.Method == VerificationTXTExistsOrValueRegex) && len(v.TXTValueRegexes) == 0 {
		return fmt.Errorf("%s requires txt_value_regexes", v.Method)
	}
	return nil
}

func validateTemplateRequirements(rule ProviderRule) error {
	if rule.Verification == nil {
		return nil
	}
	for _, tmpl := range rule.Verification.TXTTemplates {
		tokens := templateutil.Tokens(tmpl)
		for _, token := range tokens {
			switch {
			case token == "owner" && rule.Extraction.Type == ExtractionNone:
				return fmt.Errorf("template %q uses owner but extraction type is none", tmpl)
			case token == "parent" && (!rule.Verification.Inheritance.Enabled || rule.Verification.Inheritance.MaxParentLevels <= 0):
				return fmt.Errorf("template %q uses parent but inheritance is disabled", tmpl)
			case strings.HasPrefix(token, "parents[") && (!rule.Verification.Inheritance.Enabled || rule.Verification.Inheritance.MaxParentLevels <= 0):
				return fmt.Errorf("template %q uses parents[n] but inheritance is disabled", tmpl)
			}
		}
	}
	return nil
}

func (r ProviderRule) MatchTarget(target string) (bool, string) {
	target = domainutil.NormalizeName(target)
	for _, suffix := range r.Match.TargetSuffixes {
		if domainutil.MatchSuffix(target, suffix) {
			return true, fmt.Sprintf("cname suffix matched %s", suffix)
		}
	}
	for _, re := range r.compiledTargetRegexes {
		if re.MatchString(target) {
			return true, fmt.Sprintf("cname matched regex %s", re.String())
		}
	}
	return false, ""
}

func (r ProviderRule) MatchNameserver(ns string) (bool, string) {
	ns = domainutil.NormalizeName(ns)
	for _, suffix := range r.Match.NSSuffixes {
		if domainutil.MatchSuffix(ns, suffix) {
			return true, fmt.Sprintf("delegation NS suffix matched %s", suffix)
		}
	}
	for _, re := range r.compiledTargetRegexes {
		if re.MatchString(ns) {
			return true, fmt.Sprintf("delegation NS matched regex %s", re.String())
		}
	}
	return false, ""
}

func (r ProviderRule) ExtractOwner(target string) (owner string, label string, reason string, err error) {
	target = domainutil.NormalizeName(target)
	switch r.Extraction.Type {
	case ExtractionNone:
		return "", "", "", nil
	case ExtractionLabelBeforeSuffix:
		label, err := domainutil.LabelBeforeSuffix(target, r.Extraction.Suffix)
		if err != nil {
			return "", "", "", err
		}
		return label, label, fmt.Sprintf("owner extracted from label before %s", r.Extraction.Suffix), nil
	case ExtractionRegexCapture:
		matches := r.compiledExtractRegex.FindStringSubmatch(target)
		if len(matches) <= r.Extraction.CaptureGroup {
			return "", "", "", fmt.Errorf("regex capture group %d missing for %q", r.Extraction.CaptureGroup, target)
		}
		value := matches[r.Extraction.CaptureGroup]
		return value, value, fmt.Sprintf("owner extracted with regex %s", r.compiledExtractRegex.String()), nil
	default:
		return "", "", "", fmt.Errorf("unsupported extraction type %q", r.Extraction.Type)
	}
}

func (r Root) Filter(allowlist map[string]struct{}) Root {
	if len(allowlist) == 0 {
		return r
	}
	filtered := Root{Providers: make([]ProviderRule, 0, len(r.Providers))}
	for _, provider := range r.Providers {
		if _, ok := allowlist[provider.Name]; ok {
			filtered.Providers = append(filtered.Providers, provider)
		}
	}
	return filtered
}

func (r Root) EnabledProviders() []ProviderRule {
	out := make([]ProviderRule, 0, len(r.Providers))
	for _, provider := range r.Providers {
		if provider.Enabled {
			out = append(out, provider)
		}
	}
	return out
}

func (p ProviderRule) GetCompiledValueRegexes() []*regexp.Regexp {
	return p.compiledValueRegexes
}
