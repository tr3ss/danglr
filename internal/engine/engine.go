package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"

	"danglr/internal/cache"
	"danglr/internal/dnsresolver"
	"danglr/internal/domainutil"
	"danglr/internal/output"
	"danglr/internal/providers"
	templateutil "danglr/internal/template"
)

type Config struct {
	Concurrency   int
	MaxCNAMEDepth int
	Verbose       bool
}

type Engine struct {
	discoveryResolver  dnsresolver.Resolver
	validationResolver dnsresolver.Resolver
	providers          []providers.ProviderRule
	protectedOut       output.Writer
	unprotectedOut     output.Writer
	findingsOut        output.Writer
	errorsOut          output.Writer
	concurrency        int
	maxCNAMEDepth      int
	logger             *log.Logger
	txtCache           *cache.TXTCache
	discoveryNSCache   *cache.NSCache
	validationNSCache  *cache.NSCache
	stats              stats
}

type stats struct {
	totalInputs     atomic.Uint64
	providerMatches atomic.Uint64
	protected       atomic.Uint64
	unprotected     atomic.Uint64
	findings        atomic.Uint64
	errors          atomic.Uint64
}

func New(cfg Config, discoveryResolver, validationResolver dnsresolver.Resolver, rules []providers.ProviderRule, protectedOut, unprotectedOut, findingsOut, errorsOut output.Writer, logger *log.Logger) *Engine {
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 100
	}
	maxDepth := cfg.MaxCNAMEDepth
	if maxDepth <= 0 {
		maxDepth = 8
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	if validationResolver == nil {
		validationResolver = discoveryResolver
	}
	if discoveryResolver == nil {
		discoveryResolver = validationResolver
	}
	return &Engine{
		discoveryResolver:  discoveryResolver,
		validationResolver: validationResolver,
		providers:          slices.Clone(rules),
		protectedOut:       protectedOut,
		unprotectedOut:     unprotectedOut,
		findingsOut:        findingsOut,
		errorsOut:          errorsOut,
		concurrency:        concurrency,
		maxCNAMEDepth:      maxDepth,
		logger:             logger,
		txtCache:           cache.NewTXTCache(validationResolver),
		discoveryNSCache:   cache.NewNSCache(discoveryResolver),
		validationNSCache:  cache.NewNSCache(validationResolver),
	}
}

func (e *Engine) Run(ctx context.Context, input io.Reader) (output.Summary, error) {
	jobs := make(chan string, e.concurrency*2)
	var workers sync.WaitGroup

	for i := 0; i < e.concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for host := range jobs {
				e.processHost(ctx, host)
			}
		}()
	}

	scanErr := e.feedJobs(ctx, input, jobs)
	close(jobs)
	workers.Wait()

	summary := e.Summary()
	if scanErr != nil {
		return summary, scanErr
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return summary, err
	}
	return summary, ctx.Err()
}

func (e *Engine) feedJobs(ctx context.Context, input io.Reader, jobs chan<- string) error {
	sc := bufio.NewScanner(input)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := domainutil.NormalizeName(line)
		if host == "" {
			continue
		}
		e.stats.totalInputs.Add(1)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case jobs <- host:
		}
	}
	return sc.Err()
}

func (e *Engine) processHost(ctx context.Context, host string) {
	if err := ctx.Err(); err != nil {
		return
	}

	e.processCNAMEProviders(ctx, host)
	e.processNSProviders(ctx, host)
}

func (e *Engine) processCNAMEProviders(ctx context.Context, host string) {
	cnameProviders := filterProvidersByDNSRecord(e.providers, "cname")
	if len(cnameProviders) == 0 {
		return
	}

	discoveryCNAME, err := e.discoveryResolver.ResolveCNAME(ctx, host, e.maxCNAMEDepth)
	if err != nil {
		e.writeError(output.ErrorRecord{
			Host:         host,
			Stage:        "resolve_cname_discovery",
			Error:        err.Error(),
			ResolverUsed: resolverUsed(err, discoveryCNAME.ResolverUsed),
		})
		return
	}
	if !discoveryCNAME.Found {
		return
	}

	matched := make([]providers.ProviderRule, 0, len(cnameProviders))
	for _, rule := range cnameProviders {
		if ok, _ := rule.MatchTarget(discoveryCNAME.FinalName); ok {
			matched = append(matched, rule)
		}
	}
	if len(matched) == 0 {
		return
	}

	validatedCNAME := discoveryCNAME
	if e.validationResolver != e.discoveryResolver {
		validatedCNAME, err = e.validationResolver.ResolveCNAME(ctx, host, e.maxCNAMEDepth)
		if err != nil {
			for _, rule := range matched {
				e.writeError(output.ErrorRecord{
					Host:         host,
					Provider:     rule.Name,
					Stage:        "resolve_cname_validation",
					Error:        err.Error(),
					ResolverUsed: resolverUsed(err, discoveryCNAME.ResolverUsed),
				})
			}
			return
		}
		if !validatedCNAME.Found {
			return
		}
	}

	matchCtx := providers.MatchContext{
		Host:        host,
		FinalTarget: validatedCNAME.FinalName,
		CNAMEChain:  slices.Clone(validatedCNAME.Chain),
	}

	for _, rule := range matched {
		if err := e.evaluateCNAMEProvider(ctx, matchCtx, validatedCNAME.ResolverUsed, rule); err != nil {
			e.writeError(output.ErrorRecord{
				Host:         host,
				Provider:     rule.Name,
				Stage:        "evaluate_provider",
				Error:        err.Error(),
				ResolverUsed: resolverUsed(err, validatedCNAME.ResolverUsed),
			})
		}
	}
}

func (e *Engine) processNSProviders(ctx context.Context, host string) {
	nsProviders := filterProvidersByDNSRecord(e.providers, "ns")
	if len(nsProviders) == 0 {
		return
	}
	for _, rule := range nsProviders {
		if err := e.evaluateNSProvider(ctx, host, rule); err != nil {
			e.writeError(output.ErrorRecord{
				Host:     host,
				Provider: rule.Name,
				Stage:    "evaluate_provider",
				Error:    err.Error(),
			})
		}
	}
}

func (e *Engine) evaluateCNAMEProvider(ctx context.Context, matchCtx providers.MatchContext, resolverName string, rule providers.ProviderRule) error {
	matched, matchReason := rule.MatchTarget(matchCtx.FinalTarget)
	if !matched {
		return nil
	}

	verificationCtx := providers.VerificationContext{
		Host:          matchCtx.Host,
		ParentDomains: domainutil.ParentDomains(matchCtx.Host, 10),
		Apex:          domainutil.Apex(matchCtx.Host),
		FinalTarget:   matchCtx.FinalTarget,
	}

	owner, label, extractReason, err := rule.ExtractOwner(matchCtx.FinalTarget)
	if err != nil {
		return fmt.Errorf("extract owner: %w", err)
	}
	verificationCtx.Owner = owner
	verificationCtx.LabelBeforeSuffix = label

	detectionReason := matchReason
	if extractReason != "" {
		detectionReason = detectionReason + "; " + extractReason
	}

	switch rule.DetectionMode {
	case providers.DetectionModeTXTProtection:
		return e.evaluateTXTProtection(ctx, rule, matchCtx, verificationCtx, detectionReason, resolverName)
	case providers.DetectionModeClaimableTarget:
		return e.evaluateClaimableTarget(rule, matchCtx, detectionReason, resolverName)
	case providers.DetectionModePlatformHeuristic:
		return e.evaluateHeuristic(rule, matchCtx, detectionReason, resolverName)
	default:
		return fmt.Errorf("unsupported cname detection mode %q", rule.DetectionMode)
	}
}

func (e *Engine) evaluateNSProvider(ctx context.Context, host string, rule providers.ProviderRule) error {
	maxWalk := 0
	if rule.Delegation != nil {
		maxWalk = rule.Delegation.MaxParentWalk
	}
	zones := domainutil.ZoneCandidates(host, maxWalk)
	for _, zone := range zones {
		discoveryNS, err := e.discoveryNSCache.Lookup(ctx, zone)
		if err != nil {
			e.writeError(output.ErrorRecord{
				Host:         host,
				Provider:     rule.Name,
				Stage:        "lookup_ns_discovery",
				Error:        err.Error(),
				ResolverUsed: resolverUsed(err, ""),
			})
			continue
		}
		matchedNSList, reasons := matchedNameserverList(rule, discoveryNS.Nameservers)
		if len(matchedNSList) == 0 {
			continue
		}

		validatedNS := discoveryNS
		if e.validationResolver != e.discoveryResolver {
			validatedNS, err = e.validationNSCache.Lookup(ctx, zone)
			if err != nil {
				e.writeError(output.ErrorRecord{
					Host:         host,
					Provider:     rule.Name,
					Stage:        "lookup_ns_validation",
					Error:        err.Error(),
					ResolverUsed: resolverUsed(err, discoveryNS.ResolverUsed),
				})
				continue
			}
			matchedNSList, reasons = matchedNameserverList(rule, validatedNS.Nameservers)
			if len(matchedNSList) == 0 {
				continue
			}
		}

		if err := e.evaluateOrphanedDelegation(ctx, rule, host, zone, validatedNS, matchedNSList, reasons); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) evaluateTXTProtection(ctx context.Context, rule providers.ProviderRule, matchCtx providers.MatchContext, verificationCtx providers.VerificationContext, detectionReason, resolverName string) error {
	txtNames, templateReason, err := deriveTXTNames(rule, verificationCtx)
	if err != nil {
		return err
	}
	if templateReason != "" {
		detectionReason = detectionReason + "; " + templateReason
	}

	var hits []string
	resolverUsed := resolverName
	for _, txtName := range txtNames {
		result, err := e.txtCache.Lookup(ctx, txtName)
		if err != nil {
			return fmt.Errorf("lookup txt %s: %w", txtName, err)
		}
		if result.ResolverUsed != "" {
			resolverUsed = result.ResolverUsed
		}
		if txtProtected(rule, result) {
			hits = append(hits, txtName)
		}
	}

	record := output.ProtectionRecord{
		Host:                     matchCtx.Host,
		Provider:                 rule.Name,
		Class:                    rule.Class,
		DetectionMode:            rule.DetectionMode,
		MatchedTarget:            matchCtx.FinalTarget,
		FinalCNAME:               matchCtx.FinalTarget,
		Owner:                    verificationCtx.Owner,
		CheckedTXTNames:          txtNames,
		TXTHits:                  hits,
		DetectionReason:          detectionReason,
		ResolverUsed:             resolverUsed,
		Severity:                 rule.Severity,
		Confidence:               rule.Confidence,
		Tags:                     slices.Clone(rule.Tags),
		ManualValidationRequired: rule.ManualValidationRequired,
	}
	e.stats.providerMatches.Add(1)
	if len(hits) > 0 {
		record.Status = "protected"
		record.ProtectionReason = fmt.Sprintf("TXT exists at %s", strings.Join(hits, ", "))
		e.stats.protected.Add(1)
		if err := e.protectedOut.Write(record); err != nil {
			return fmt.Errorf("write protected output: %w", err)
		}
	} else {
		record.Status = "unprotected"
		record.ProtectionReason = "No matching TXT record found"
		e.stats.unprotected.Add(1)
		if err := e.unprotectedOut.Write(record); err != nil {
			return fmt.Errorf("write unprotected output: %w", err)
		}
	}
	e.logDecision(record.Status, matchCtx.Host, matchCtx.FinalTarget, rule.Name)
	return nil
}

func (e *Engine) evaluateClaimableTarget(rule providers.ProviderRule, matchCtx providers.MatchContext, detectionReason, resolverUsed string) error {
	record := output.FindingRecord{
		Host:                     matchCtx.Host,
		Provider:                 rule.Name,
		Class:                    rule.Class,
		DetectionMode:            rule.DetectionMode,
		MatchedTarget:            matchCtx.FinalTarget,
		FinalCNAME:               matchCtx.FinalTarget,
		FindingType:              rule.Dangling.ClassifyAs,
		Evidence:                 []string{fmt.Sprintf("matched target %s", matchCtx.FinalTarget)},
		DetectionReason:          detectionReason,
		ResolverUsed:             resolverUsed,
		Status:                   "finding",
		Severity:                 rule.Severity,
		Confidence:               rule.Confidence,
		Tags:                     slices.Clone(rule.Tags),
		ManualValidationRequired: rule.ManualValidationRequired || rule.Confidence != "high",
	}
	e.stats.providerMatches.Add(1)
	e.stats.findings.Add(1)
	if err := e.findingsOut.Write(record); err != nil {
		return fmt.Errorf("write findings output: %w", err)
	}
	e.logDecision(record.Status, matchCtx.Host, matchCtx.FinalTarget, rule.Name)
	return nil
}

func (e *Engine) evaluateHeuristic(rule providers.ProviderRule, matchCtx providers.MatchContext, detectionReason, resolverUsed string) error {
	record := output.FindingRecord{
		Host:                     matchCtx.Host,
		Provider:                 rule.Name,
		Class:                    rule.Class,
		DetectionMode:            rule.DetectionMode,
		MatchedTarget:            matchCtx.FinalTarget,
		FinalCNAME:               matchCtx.FinalTarget,
		FindingType:              rule.Heuristic.ClassifyAs,
		Evidence:                 []string{fmt.Sprintf("matched target %s", matchCtx.FinalTarget)},
		DetectionReason:          detectionReason,
		ResolverUsed:             resolverUsed,
		Status:                   "finding",
		Severity:                 rule.Severity,
		Confidence:               rule.Confidence,
		Tags:                     slices.Clone(rule.Tags),
		ManualValidationRequired: true,
	}
	e.stats.providerMatches.Add(1)
	e.stats.findings.Add(1)
	if err := e.findingsOut.Write(record); err != nil {
		return fmt.Errorf("write findings output: %w", err)
	}
	e.logDecision(record.Status, matchCtx.Host, matchCtx.FinalTarget, rule.Name)
	return nil
}

func (e *Engine) evaluateOrphanedDelegation(ctx context.Context, rule providers.ProviderRule, host, zone string, nsResult dnsresolver.NSLookupResult, matchedNS, matchReasons []string) error {
	detectionReason := strings.Join(matchReasons, "; ")
	evidence := []string{
		fmt.Sprintf("delegated zone %s", zone),
		fmt.Sprintf("recursive NS for %s: %s", zone, strings.Join(nsResult.Nameservers, ", ")),
	}

	suspiciousResponses := 0
	successResponses := 0
	resolverUsed := nsResult.ResolverUsed
	for _, server := range matchedNS {
		soa, err := e.validationResolver.LookupSOAAtServer(ctx, zone, server)
		if err != nil {
			evidence = append(evidence, fmt.Sprintf("SOA @ %s error: %v", server, err))
			continue
		}
		if soa.ResolverUsed != "" {
			resolverUsed = soa.ResolverUsed
		}
		successResponses++
		evidence = append(evidence, fmt.Sprintf("SOA @ %s => rcode=%s authoritative=%t found=%t", server, dns.RcodeToString[soa.Rcode], soa.Authoritative, soa.Found))
		if soa.Found && (!rule.Delegation.RequireAuthoritativeSOA || soa.Authoritative) {
			return nil
		}
		if isSuspiciousDelegationSOA(rule, soa) {
			suspiciousResponses++
		}
	}

	if successResponses == 0 {
		return nil
	}
	if suspiciousResponses == 0 {
		return nil
	}

	record := output.FindingRecord{
		Host:                     host,
		Provider:                 rule.Name,
		Class:                    rule.Class,
		DetectionMode:            rule.DetectionMode,
		MatchedTarget:            zone,
		FinalCNAME:               "",
		FindingType:              rule.Delegation.ClassifyAs,
		Evidence:                 evidence,
		DetectionReason:          detectionReason,
		ResolverUsed:             resolverUsed,
		Status:                   "finding",
		Severity:                 rule.Severity,
		Confidence:               rule.Confidence,
		Tags:                     slices.Clone(rule.Tags),
		ManualValidationRequired: true,
	}
	e.stats.providerMatches.Add(1)
	e.stats.findings.Add(1)
	if err := e.findingsOut.Write(record); err != nil {
		return fmt.Errorf("write findings output: %w", err)
	}
	e.logDecision(record.Status, host, zone, rule.Name)
	return nil
}

func deriveTXTNames(rule providers.ProviderRule, ctx providers.VerificationContext) ([]string, string, error) {
	parentLimit := 0
	if rule.Verification.Inheritance.Enabled {
		parentLimit = rule.Verification.Inheritance.MaxParentLevels
	}
	parentDomains := ctx.ParentDomains
	if parentLimit < len(parentDomains) {
		parentDomains = parentDomains[:parentLimit]
	}

	reasons := make([]string, 0, len(rule.Verification.TXTTemplates))
	seen := make(map[string]struct{})
	var names []string
	for _, tmpl := range rule.Verification.TXTTemplates {
		if templateutil.UsesParentToken(tmpl) {
			for _, parent := range parentDomains {
				name, err := templateutil.Render(tmpl, templateutil.Context{
					Host:              ctx.Host,
					Parent:            parent,
					Parents:           ctx.ParentDomains,
					Apex:              ctx.Apex,
					Owner:             ctx.Owner,
					Target:            ctx.FinalTarget,
					LabelBeforeSuffix: ctx.LabelBeforeSuffix,
				})
				if err != nil {
					return nil, "", fmt.Errorf("render template %q: %w", tmpl, err)
				}
				if name == "" {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				names = append(names, name)
			}
		} else {
			name, err := templateutil.Render(tmpl, templateutil.Context{
				Host:              ctx.Host,
				Parent:            firstParent(ctx.ParentDomains),
				Parents:           ctx.ParentDomains,
				Apex:              ctx.Apex,
				Owner:             ctx.Owner,
				Target:            ctx.FinalTarget,
				LabelBeforeSuffix: ctx.LabelBeforeSuffix,
			})
			if err != nil {
				return nil, "", fmt.Errorf("render template %q: %w", tmpl, err)
			}
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
		reasons = append(reasons, fmt.Sprintf("checked TXT template %s", tmpl))
	}
	return names, strings.Join(reasons, "; "), nil
}

func txtProtected(rule providers.ProviderRule, result dnsresolver.TXTLookupResult) bool {
	switch rule.Verification.Method {
	case providers.VerificationTXTExists:
		return result.Found
	case providers.VerificationTXTValueRegex:
		return anyTXTValueMatches(rule, result.Values)
	case providers.VerificationTXTExistsOrValueRegex:
		return result.Found || anyTXTValueMatches(rule, result.Values)
	default:
		return false
	}
}

func anyTXTValueMatches(rule providers.ProviderRule, values []string) bool {
	for _, value := range values {
		for _, re := range ruleCompiledValueRegexes(rule) {
			if re.MatchString(value) {
				return true
			}
		}
	}
	return false
}

func ruleCompiledValueRegexes(rule providers.ProviderRule) []*regexp.Regexp {
	return rule.GetCompiledValueRegexes()
}

func matchedNameserverList(rule providers.ProviderRule, nameservers []string) ([]string, []string) {
	var matches []string
	var reasons []string
	seenReason := make(map[string]struct{})
	for _, ns := range nameservers {
		if ok, reason := rule.MatchNameserver(ns); ok {
			matches = append(matches, ns)
			if _, exists := seenReason[reason]; !exists {
				seenReason[reason] = struct{}{}
				reasons = append(reasons, reason)
			}
		}
	}
	return matches, reasons
}

func isSuspiciousDelegationSOA(rule providers.ProviderRule, soa dnsresolver.SOALookupResult) bool {
	if soa.Found && (!rule.Delegation.RequireAuthoritativeSOA || soa.Authoritative) {
		return false
	}
	if len(rule.Delegation.AuthoritativeRCodes) == 0 {
		return !soa.Found
	}
	rcode := strings.ToLower(dns.RcodeToString[soa.Rcode])
	for _, allowed := range rule.Delegation.AuthoritativeRCodes {
		if rcode == allowed {
			return true
		}
	}
	return !soa.Found
}

func filterProvidersByDNSRecord(rules []providers.ProviderRule, dnsRecord string) []providers.ProviderRule {
	out := make([]providers.ProviderRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Enabled && rule.Match.DNSRecord == dnsRecord {
			out = append(out, rule)
		}
	}
	return out
}

func (e *Engine) Summary() output.Summary {
	return output.Summary{
		TotalInputHosts: e.stats.totalInputs.Load(),
		ProviderMatches: e.stats.providerMatches.Load(),
		Protected:       e.stats.protected.Load(),
		Unprotected:     e.stats.unprotected.Load(),
		Findings:        e.stats.findings.Load(),
		Errors:          e.stats.errors.Load(),
	}
}

func (e *Engine) writeError(record output.ErrorRecord) {
	e.stats.errors.Add(1)
	if e.errorsOut != nil {
		_ = e.errorsOut.Write(record)
	}
}

func (e *Engine) Close() error {
	var errs []error
	for _, writer := range []output.Writer{e.protectedOut, e.unprotectedOut, e.findingsOut, e.errorsOut} {
		if writer == nil {
			continue
		}
		if err := writer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("close outputs: %v", errs)
}

func (e *Engine) logDecision(status, host, target, provider string) {
	if e.logger != nil && e.logger.Writer() != io.Discard {
		e.logger.Printf("%s %s -> %s (%s)", status, host, target, provider)
	}
}

func resolverUsed(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	var lookupErr *dnsresolver.LookupError
	if errors.As(err, &lookupErr) && lookupErr.ResolverUsed != "" {
		return lookupErr.ResolverUsed
	}
	return fallback
}

func firstParent(parents []string) string {
	if len(parents) == 0 {
		return ""
	}
	return parents[0]
}
