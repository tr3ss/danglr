package providers

import "testing"

func TestProviderMatchBySuffix(t *testing.T) {
	rule := ProviderRule{
		Name:          "github-pages",
		Enabled:       true,
		Class:         ClassStrongSignal,
		DetectionMode: DetectionModeTXTProtection,
		Confidence:    "high",
		Match: MatchRule{
			DNSRecord:      "cname",
			TargetSuffixes: []string{"github.io"},
		},
		Extraction: ExtractionRule{Type: ExtractionLabelBeforeSuffix, Suffix: "github.io"},
		Verification: &VerificationRule{
			Method:       VerificationTXTExists,
			TXTTemplates: []string{"_github-pages-challenge-{{owner}}.{{host}}"},
			Inheritance: InheritanceRule{
				Enabled:         false,
				MaxParentLevels: 0,
			},
		},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	matched, _ := rule.MatchTarget("foo.bar.github.io")
	if !matched {
		t.Fatalf("expected match")
	}
}

func TestProviderMatchByRegex(t *testing.T) {
	rule := ProviderRule{
		Name:          "aws-s3-website",
		Enabled:       true,
		Class:         ClassLegacyDangling,
		DetectionMode: DetectionModeClaimableTarget,
		Confidence:    "medium",
		Match: MatchRule{
			DNSRecord:           "cname",
			TargetSuffixRegexes: []string{`(^|\.)s3-website[.-][a-z0-9-]+\.amazonaws\.com\.?$`},
		},
		Extraction: ExtractionRule{Type: ExtractionNone},
		Dangling:   &DanglingRule{Method: DanglingDNSTargetPatternOnly, ClassifyAs: "likely-dangling-s3"},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	matched, _ := rule.MatchTarget("bucket.s3-website-us-east-1.amazonaws.com")
	if !matched {
		t.Fatalf("expected regex match")
	}
}

func TestOwnerExtractionGithubStyle(t *testing.T) {
	rule := ProviderRule{
		Name:          "github-pages",
		Enabled:       true,
		Class:         ClassStrongSignal,
		DetectionMode: DetectionModeTXTProtection,
		Confidence:    "high",
		Match: MatchRule{
			DNSRecord:      "cname",
			TargetSuffixes: []string{"github.io"},
		},
		Extraction: ExtractionRule{Type: ExtractionLabelBeforeSuffix, Suffix: "github.io"},
		Verification: &VerificationRule{
			Method:       VerificationTXTExists,
			TXTTemplates: []string{"_github-pages-challenge-{{owner}}.{{host}}"},
			Inheritance:  InheritanceRule{},
		},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	owner, _, _, err := rule.ExtractOwner("foo.bar.github.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "bar" {
		t.Fatalf("got %q want %q", owner, "bar")
	}
}

func TestOrphanedDelegationProviderValidationAndNSMatch(t *testing.T) {
	rule := ProviderRule{
		Name:          "aws-route53-delegation",
		Enabled:       true,
		Class:         ClassLegacyDangling,
		DetectionMode: DetectionModeOrphanedDelegation,
		Confidence:    "medium",
		Match: MatchRule{
			DNSRecord: "ns",
			NSRegexes: []string{`(^|\.)ns-[0-9]+\.awsdns-[0-9]+\.(com|net)\.?$`},
		},
		Extraction: ExtractionRule{Type: ExtractionNone},
		Delegation: &DelegationRule{
			Method:                    DelegationParentWithMissingZone,
			ClassifyAs:                "likely-orphaned-route53-delegation",
			RequireParentNSDelegation: true,
			RequireAuthoritativeSOA:   true,
			AuthoritativeRCodes:       []string{"refused"},
			DirectNSValidation:        true,
			MaxParentWalk:             1,
		},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	matched, _ := rule.MatchNameserver("ns-123.awsdns-45.com")
	if !matched {
		t.Fatalf("expected ns match")
	}
}
