package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"danglr/internal/config"
	"danglr/internal/dnsresolver"
	"danglr/internal/output"
	"danglr/internal/providers"
)

type mockResolver struct {
	mu         sync.Mutex
	cname      map[string]dnsresolver.CNAMELookupResult
	cnameErr   map[string]error
	txt        map[string]dnsresolver.TXTLookupResult
	txtErr     map[string]error
	txtCalls   map[string]int
	ns         map[string]dnsresolver.NSLookupResult
	nsErr      map[string]error
	nsCalls    map[string]int
	soa        map[string]dnsresolver.SOALookupResult
	soaErr     map[string]error
	soaCalls   map[string]int
	soaAt      map[string]dnsresolver.SOALookupResult
	soaAtErr   map[string]error
	soaAtCalls map[string]int
}

func (m *mockResolver) ResolveCNAME(_ context.Context, host string, _ int) (dnsresolver.CNAMELookupResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.cnameErr[host]; err != nil {
		return dnsresolver.CNAMELookupResult{}, err
	}
	return m.cname[host], nil
}

func (m *mockResolver) LookupTXT(_ context.Context, name string) (dnsresolver.TXTLookupResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.txtCalls == nil {
		m.txtCalls = make(map[string]int)
	}
	m.txtCalls[name]++
	if err := m.txtErr[name]; err != nil {
		return dnsresolver.TXTLookupResult{}, err
	}
	if result, ok := m.txt[name]; ok {
		return result, nil
	}
	return dnsresolver.TXTLookupResult{Name: name, Found: false}, nil
}

func (m *mockResolver) LookupNS(_ context.Context, name string) (dnsresolver.NSLookupResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nsCalls == nil {
		m.nsCalls = make(map[string]int)
	}
	m.nsCalls[name]++
	if err := m.nsErr[name]; err != nil {
		return dnsresolver.NSLookupResult{}, err
	}
	if result, ok := m.ns[name]; ok {
		return result, nil
	}
	return dnsresolver.NSLookupResult{Name: name, Found: false}, nil
}

func (m *mockResolver) LookupSOA(_ context.Context, name string) (dnsresolver.SOALookupResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.soaCalls == nil {
		m.soaCalls = make(map[string]int)
	}
	m.soaCalls[name]++
	if err := m.soaErr[name]; err != nil {
		return dnsresolver.SOALookupResult{}, err
	}
	if result, ok := m.soa[name]; ok {
		return result, nil
	}
	return dnsresolver.SOALookupResult{Name: name, Found: false}, nil
}

func (m *mockResolver) LookupSOAAtServer(_ context.Context, name, server string) (dnsresolver.SOALookupResult, error) {
	key := name + "@" + server
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.soaAtCalls == nil {
		m.soaAtCalls = make(map[string]int)
	}
	m.soaAtCalls[key]++
	if err := m.soaAtErr[key]; err != nil {
		return dnsresolver.SOALookupResult{}, err
	}
	if result, ok := m.soaAt[key]; ok {
		return result, nil
	}
	return dnsresolver.SOALookupResult{Name: name, ResolverUsed: server, Found: false}, nil
}

type memoryWriter struct {
	mu      sync.Mutex
	records []any
}

func (w *memoryWriter) Write(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records = append(w.records, v)
	return nil
}

func (w *memoryWriter) Close() error { return nil }

func (w *memoryWriter) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.records)
}

func (w *memoryWriter) Records() []any {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]any, len(w.records))
	copy(out, w.records)
	return out
}

func TestTXTDecisionModes(t *testing.T) {
	rule := providers.ProviderRule{
		Name:          "example",
		Enabled:       true,
		Class:         providers.ClassStrongSignal,
		DetectionMode: providers.DetectionModeTXTProtection,
		Confidence:    "high",
		Match: providers.MatchRule{
			DNSRecord:      "cname",
			TargetSuffixes: []string{"example.net"},
		},
		Extraction: providers.ExtractionRule{Type: providers.ExtractionNone},
		Verification: &providers.VerificationRule{
			Method:          providers.VerificationTXTValueRegex,
			TXTTemplates:    []string{"token.{{host}}"},
			TXTValueRegexes: []string{"^match$"},
			Inheritance:     providers.InheritanceRule{},
		},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if txtProtected(rule, dnsresolver.TXTLookupResult{Found: true, Values: []string{"nope"}}) {
		t.Fatalf("expected no match")
	}
	if !txtProtected(rule, dnsresolver.TXTLookupResult{Found: true, Values: []string{"match"}}) {
		t.Fatalf("expected regex match")
	}
}

func TestInheritanceBehavior(t *testing.T) {
	rule := providers.ProviderRule{
		Name:          "github-pages",
		Enabled:       true,
		Class:         providers.ClassStrongSignal,
		DetectionMode: providers.DetectionModeTXTProtection,
		Confidence:    "high",
		Match: providers.MatchRule{
			DNSRecord:      "cname",
			TargetSuffixes: []string{"github.io"},
		},
		Extraction: providers.ExtractionRule{Type: providers.ExtractionLabelBeforeSuffix, Suffix: "github.io"},
		Verification: &providers.VerificationRule{
			Method:       providers.VerificationTXTExists,
			TXTTemplates: []string{"_github-pages-challenge-{{owner}}.{{parent}}"},
			Inheritance: providers.InheritanceRule{
				Enabled:         true,
				MaxParentLevels: 2,
			},
		},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names, _, err := deriveTXTNames(rule, providers.VerificationContext{
		Host:          "a.b.example.com",
		ParentDomains: []string{"b.example.com", "example.com"},
		Owner:         "octocat",
		FinalTarget:   "octocat.github.io",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("got %v", names)
	}
}

func TestMultiProviderMatchingAndRouting(t *testing.T) {
	rules := []providers.ProviderRule{
		mustRule(t, providers.ProviderRule{
			Name:          "github-pages-a",
			Enabled:       true,
			Class:         providers.ClassStrongSignal,
			DetectionMode: providers.DetectionModeTXTProtection,
			Confidence:    "high",
			Severity:      "medium",
			Match: providers.MatchRule{
				DNSRecord:      "cname",
				TargetSuffixes: []string{"github.io"},
			},
			Extraction: providers.ExtractionRule{Type: providers.ExtractionLabelBeforeSuffix, Suffix: "github.io"},
			Verification: &providers.VerificationRule{
				Method:       providers.VerificationTXTExists,
				TXTTemplates: []string{"_github-pages-challenge-{{owner}}.{{host}}"},
				Inheritance:  providers.InheritanceRule{},
			},
		}),
		mustRule(t, providers.ProviderRule{
			Name:          "github-pages-b",
			Enabled:       true,
			Class:         providers.ClassHeuristic,
			DetectionMode: providers.DetectionModePlatformHeuristic,
			Confidence:    "low",
			Severity:      "info",
			Match: providers.MatchRule{
				DNSRecord:      "cname",
				TargetSuffixes: []string{"github.io"},
			},
			Extraction: providers.ExtractionRule{Type: providers.ExtractionNone},
			Heuristic:  &providers.HeuristicRule{Method: providers.HeuristicProviderTargetOnly, ClassifyAs: "manual-check"},
		}),
	}
	resolver := &mockResolver{
		cname: map[string]dnsresolver.CNAMELookupResult{
			"blog.example.com": {Found: true, FinalName: "octocat.github.io", Chain: []string{"blog.example.com", "octocat.github.io"}, ResolverUsed: "r1"},
		},
		cnameErr: map[string]error{},
		txt: map[string]dnsresolver.TXTLookupResult{
			"_github-pages-challenge-octocat.blog.example.com": {Name: "_github-pages-challenge-octocat.blog.example.com", Found: true, ResolverUsed: "r2"},
		},
		txtErr:   map[string]error{},
		txtCalls: map[string]int{},
	}
	protected := &memoryWriter{}
	unprotected := &memoryWriter{}
	findings := &memoryWriter{}
	errs := &memoryWriter{}

	e := New(Config{Concurrency: 1}, resolver, resolver, rules, protected, unprotected, findings, errs, nil)
	summary, err := e.Run(context.Background(), strings.NewReader("blog.example.com\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.ProviderMatches != 2 {
		t.Fatalf("got provider matches=%d want 2", summary.ProviderMatches)
	}
	if protected.Len() != 1 || findings.Len() != 1 || unprotected.Len() != 0 {
		t.Fatalf("unexpected routing protected=%d findings=%d unprotected=%d", protected.Len(), findings.Len(), unprotected.Len())
	}
}

func TestCacheDeduplication(t *testing.T) {
	rules := []providers.ProviderRule{mustRule(t, providers.ProviderRule{
		Name:          "github-pages",
		Enabled:       true,
		Class:         providers.ClassStrongSignal,
		DetectionMode: providers.DetectionModeTXTProtection,
		Confidence:    "high",
		Severity:      "medium",
		Match: providers.MatchRule{
			DNSRecord:      "cname",
			TargetSuffixes: []string{"github.io"},
		},
		Extraction: providers.ExtractionRule{Type: providers.ExtractionLabelBeforeSuffix, Suffix: "github.io"},
		Verification: &providers.VerificationRule{
			Method:       providers.VerificationTXTExists,
			TXTTemplates: []string{"_github-pages-challenge-{{owner}}.{{parent}}"},
			Inheritance: providers.InheritanceRule{
				Enabled:         true,
				MaxParentLevels: 1,
			},
		},
	})}
	parentTXT := "_github-pages-challenge-octocat.example.com"
	resolver := &mockResolver{
		cname: map[string]dnsresolver.CNAMELookupResult{
			"a.example.com": {Found: true, FinalName: "octocat.github.io", Chain: []string{"a.example.com", "octocat.github.io"}, ResolverUsed: "r1"},
			"b.example.com": {Found: true, FinalName: "octocat.github.io", Chain: []string{"b.example.com", "octocat.github.io"}, ResolverUsed: "r1"},
		},
		cnameErr: map[string]error{},
		txt: map[string]dnsresolver.TXTLookupResult{
			parentTXT: {Name: parentTXT, Found: true, ResolverUsed: "r2"},
		},
		txtErr:     map[string]error{},
		txtCalls:   map[string]int{},
		ns:         map[string]dnsresolver.NSLookupResult{},
		nsErr:      map[string]error{},
		nsCalls:    map[string]int{},
		soa:        map[string]dnsresolver.SOALookupResult{},
		soaErr:     map[string]error{},
		soaCalls:   map[string]int{},
		soaAt:      map[string]dnsresolver.SOALookupResult{},
		soaAtErr:   map[string]error{},
		soaAtCalls: map[string]int{},
	}
	e := New(Config{Concurrency: 2}, resolver, resolver, rules, &memoryWriter{}, &memoryWriter{}, &memoryWriter{}, &memoryWriter{}, nil)
	_, err := e.Run(context.Background(), strings.NewReader("a.example.com\nb.example.com\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolver.txtCalls[parentTXT] != 1 {
		t.Fatalf("got %d calls want 1", resolver.txtCalls[parentTXT])
	}
}

func TestFixtureIntegration(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "providers.yaml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	root, err := config.ParseProviders(data, true)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	resolver := &mockResolver{
		cname: map[string]dnsresolver.CNAMELookupResult{
			"gh-protected.example.com":      {Found: true, FinalName: "octocat.github.io", Chain: []string{"gh-protected.example.com", "octocat.github.io"}, ResolverUsed: "r1"},
			"gh-unprotected.example.org":    {Found: true, FinalName: "octocat.github.io", Chain: []string{"gh-unprotected.example.org", "octocat.github.io"}, ResolverUsed: "r1"},
			"azure-protected.example.com":   {Found: true, FinalName: "app.azurewebsites.net", Chain: []string{"azure-protected.example.com", "app.azurewebsites.net"}, ResolverUsed: "r1"},
			"azure-unprotected.example.com": {Found: true, FinalName: "app.azurewebsites.net", Chain: []string{"azure-unprotected.example.com", "app.azurewebsites.net"}, ResolverUsed: "r1"},
			"s3.example.com":                {Found: true, FinalName: "bucket.s3-website-us-east-1.amazonaws.com", Chain: []string{"s3.example.com", "bucket.s3-website-us-east-1.amazonaws.com"}, ResolverUsed: "r1"},
			"netlify.example.com":           {Found: true, FinalName: "site.netlify.app", Chain: []string{"netlify.example.com", "site.netlify.app"}, ResolverUsed: "r1"},
		},
		cnameErr: map[string]error{},
		txt: map[string]dnsresolver.TXTLookupResult{
			"_github-pages-challenge-octocat.example.com": {Name: "_github-pages-challenge-octocat.example.com", Found: true, ResolverUsed: "r2"},
			"asuid.azure-protected.example.com":           {Name: "asuid.azure-protected.example.com", Found: true, ResolverUsed: "r2"},
		},
		txtErr:   map[string]error{},
		txtCalls: map[string]int{},
		ns: map[string]dnsresolver.NSLookupResult{
			"child.example.com": {
				Name:         "child.example.com",
				Found:        true,
				Nameservers:  []string{"ns-123.awsdns-45.com", "ns-234.awsdns-56.net"},
				ResolverUsed: "r1",
			},
			"delegated.example.com": {
				Name:         "delegated.example.com",
				Found:        true,
				Nameservers:  []string{"ns1-03.azure-dns.com", "ns2-03.azure-dns.net"},
				ResolverUsed: "r1",
			},
			"cf.example.com": {
				Name:         "cf.example.com",
				Found:        true,
				Nameservers:  []string{"abby.ns.cloudflare.com", "burt.ns.cloudflare.com"},
				ResolverUsed: "r1",
			},
		},
		nsErr:    map[string]error{},
		nsCalls:  map[string]int{},
		soa:      map[string]dnsresolver.SOALookupResult{},
		soaErr:   map[string]error{},
		soaCalls: map[string]int{},
		soaAt: map[string]dnsresolver.SOALookupResult{
			"child.example.com@ns-123.awsdns-45.com": {
				Name:         "child.example.com",
				ResolverUsed: "ns-123.awsdns-45.com",
				Rcode:        5,
				Found:        false,
			},
			"child.example.com@ns-234.awsdns-56.net": {
				Name:         "child.example.com",
				ResolverUsed: "ns-234.awsdns-56.net",
				Rcode:        5,
				Found:        false,
			},
			"delegated.example.com@ns1-03.azure-dns.com": {
				Name:         "delegated.example.com",
				ResolverUsed: "ns1-03.azure-dns.com",
				Rcode:        5,
				Found:        false,
			},
			"delegated.example.com@ns2-03.azure-dns.net": {
				Name:         "delegated.example.com",
				ResolverUsed: "ns2-03.azure-dns.net",
				Rcode:        5,
				Found:        false,
			},
			"cf.example.com@abby.ns.cloudflare.com": {
				Name:         "cf.example.com",
				ResolverUsed: "abby.ns.cloudflare.com",
				Rcode:        5,
				Found:        false,
			},
			"cf.example.com@burt.ns.cloudflare.com": {
				Name:         "cf.example.com",
				ResolverUsed: "burt.ns.cloudflare.com",
				Rcode:        5,
				Found:        false,
			},
		},
		soaAtErr:   map[string]error{},
		soaAtCalls: map[string]int{},
	}
	protected := &memoryWriter{}
	unprotected := &memoryWriter{}
	findings := &memoryWriter{}
	errs := &memoryWriter{}

	e := New(Config{Concurrency: 3}, resolver, resolver, root.EnabledProviders(), protected, unprotected, findings, errs, nil)
	input := strings.NewReader(strings.Join([]string{
		"gh-protected.example.com",
		"gh-unprotected.example.org",
		"azure-protected.example.com",
		"azure-unprotected.example.com",
		"s3.example.com",
		"netlify.example.com",
		"child.example.com",
		"delegated.example.com",
		"cf.example.com",
	}, "\n") + "\n")
	summary, err := e.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Protected != 2 || summary.Unprotected != 2 || summary.Findings != 5 || summary.Errors != 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	protectedRecords := protected.Records()
	foundGitHubProtected := false
	foundAzureProtected := false
	for _, raw := range protectedRecords {
		record := raw.(output.ProtectionRecord)
		switch record.Provider {
		case "github-pages":
			foundGitHubProtected = true
		case "azure-app-service":
			foundAzureProtected = true
		}
	}
	if !foundGitHubProtected || !foundAzureProtected {
		t.Fatalf("missing protected records: %+v", protectedRecords)
	}

	unprotectedRecords := unprotected.Records()
	foundGitHubUnprotected := false
	foundAzureUnprotected := false
	for _, raw := range unprotectedRecords {
		record := raw.(output.ProtectionRecord)
		switch record.Provider {
		case "github-pages":
			foundGitHubUnprotected = true
		case "azure-app-service":
			foundAzureUnprotected = true
		}
	}
	if !foundGitHubUnprotected || !foundAzureUnprotected {
		t.Fatalf("missing unprotected records: %+v", unprotectedRecords)
	}

	findingTypes := make(map[string]bool)
	for _, raw := range findings.Records() {
		record := raw.(output.FindingRecord)
		findingTypes[record.FindingType] = true
		if !record.ManualValidationRequired {
			t.Fatalf("expected manual validation for finding %+v", record)
		}
	}
	if !findingTypes["likely-dangling-s3"] || !findingTypes["netlify-manual-validation"] || !findingTypes["likely-orphaned-route53-delegation"] || !findingTypes["likely-orphaned-azure-dns-delegation"] || !findingTypes["likely-orphaned-cloudflare-delegation"] {
		t.Fatalf("missing findings: %+v", findingTypes)
	}
}

func TestOrphanedDelegationFinding(t *testing.T) {
	rule := mustRule(t, providers.ProviderRule{
		Name:          "aws-route53-delegation",
		Enabled:       true,
		Class:         providers.ClassLegacyDangling,
		DetectionMode: providers.DetectionModeOrphanedDelegation,
		Confidence:    "medium",
		Severity:      "high",
		Match: providers.MatchRule{
			DNSRecord: "ns",
			NSRegexes: []string{`(^|\.)ns-[0-9]+\.awsdns-[0-9]+\.(com|net)\.?$`},
		},
		Extraction: providers.ExtractionRule{Type: providers.ExtractionNone},
		Delegation: &providers.DelegationRule{
			Method:                    providers.DelegationParentWithMissingZone,
			ClassifyAs:                "likely-orphaned-route53-delegation",
			RequireParentNSDelegation: true,
			RequireAuthoritativeSOA:   true,
			AuthoritativeRCodes:       []string{"refused", "servfail", "nxdomain", "noerror"},
			DirectNSValidation:        true,
			MaxParentWalk:             1,
		},
	})
	resolver := &mockResolver{
		cname:    map[string]dnsresolver.CNAMELookupResult{},
		cnameErr: map[string]error{},
		txt:      map[string]dnsresolver.TXTLookupResult{},
		txtErr:   map[string]error{},
		txtCalls: map[string]int{},
		ns: map[string]dnsresolver.NSLookupResult{
			"child.example.com": {Name: "child.example.com", Found: true, Nameservers: []string{"ns-123.awsdns-45.com"}, ResolverUsed: "r1"},
		},
		nsErr:    map[string]error{},
		nsCalls:  map[string]int{},
		soa:      map[string]dnsresolver.SOALookupResult{},
		soaErr:   map[string]error{},
		soaCalls: map[string]int{},
		soaAt: map[string]dnsresolver.SOALookupResult{
			"child.example.com@ns-123.awsdns-45.com": {Name: "child.example.com", ResolverUsed: "ns-123.awsdns-45.com", Rcode: 5, Found: false},
		},
		soaAtErr:   map[string]error{},
		soaAtCalls: map[string]int{},
	}
	findings := &memoryWriter{}
	e := New(Config{Concurrency: 1}, resolver, resolver, []providers.ProviderRule{rule}, &memoryWriter{}, &memoryWriter{}, findings, &memoryWriter{}, nil)
	summary, err := e.Run(context.Background(), strings.NewReader("child.example.com\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.Findings != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	record := findings.Records()[0].(output.FindingRecord)
	if record.FindingType != "likely-orphaned-route53-delegation" {
		t.Fatalf("unexpected finding: %+v", record)
	}
}

func TestUntrustedDiscoveryTrustedValidation(t *testing.T) {
	rule := mustRule(t, providers.ProviderRule{
		Name:          "github-pages",
		Enabled:       true,
		Class:         providers.ClassStrongSignal,
		DetectionMode: providers.DetectionModeTXTProtection,
		Confidence:    "high",
		Severity:      "medium",
		Match: providers.MatchRule{
			DNSRecord:      "cname",
			TargetSuffixes: []string{"github.io"},
		},
		Extraction: providers.ExtractionRule{Type: providers.ExtractionLabelBeforeSuffix, Suffix: "github.io"},
		Verification: &providers.VerificationRule{
			Method:       providers.VerificationTXTExists,
			TXTTemplates: []string{"_github-pages-challenge-{{owner}}.{{host}}"},
			Inheritance:  providers.InheritanceRule{},
		},
	})

	discovery := newMockResolver()
	discovery.cname["blog.example.com"] = dnsresolver.CNAMELookupResult{Found: true, FinalName: "octocat.github.io", Chain: []string{"blog.example.com", "octocat.github.io"}, ResolverUsed: "u1"}

	validation := newMockResolver()
	validation.cname["blog.example.com"] = dnsresolver.CNAMELookupResult{Found: true, FinalName: "safe.example.net", Chain: []string{"blog.example.com", "safe.example.net"}, ResolverUsed: "t1"}

	protected := &memoryWriter{}
	unprotected := &memoryWriter{}
	findings := &memoryWriter{}

	e := New(Config{Concurrency: 1}, discovery, validation, []providers.ProviderRule{rule}, protected, unprotected, findings, &memoryWriter{}, nil)
	summary, err := e.Run(context.Background(), strings.NewReader("blog.example.com\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.ProviderMatches != 0 || protected.Len() != 0 || unprotected.Len() != 0 || findings.Len() != 0 {
		t.Fatalf("unexpected validation bypass: %+v", summary)
	}
}

func mustRule(t *testing.T, rule providers.ProviderRule) providers.ProviderRule {
	t.Helper()
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate rule: %v", err)
	}
	return rule
}

func newMockResolver() *mockResolver {
	return &mockResolver{
		cname:      map[string]dnsresolver.CNAMELookupResult{},
		cnameErr:   map[string]error{},
		txt:        map[string]dnsresolver.TXTLookupResult{},
		txtErr:     map[string]error{},
		txtCalls:   map[string]int{},
		ns:         map[string]dnsresolver.NSLookupResult{},
		nsErr:      map[string]error{},
		nsCalls:    map[string]int{},
		soa:        map[string]dnsresolver.SOALookupResult{},
		soaErr:     map[string]error{},
		soaCalls:   map[string]int{},
		soaAt:      map[string]dnsresolver.SOALookupResult{},
		soaAtErr:   map[string]error{},
		soaAtCalls: map[string]int{},
	}
}
