package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

var (
	ErrNoData      = errors.New("dns no data")
	ErrNXDOMAIN    = errors.New("dns nxdomain")
	ErrMaxDepth    = errors.New("max cname depth exceeded")
	ErrCNAMELoop   = errors.New("cname loop detected")
	ErrNoResolvers = errors.New("no resolvers configured")
)

type CNAMELookupResult struct {
	Found        bool
	FinalName    string
	Chain        []string
	ResolverUsed string
	Depth        int
}

type TXTLookupResult struct {
	Name         string
	Values       []string
	Found        bool
	ResolverUsed string
}

type NSLookupResult struct {
	Name         string
	Nameservers  []string
	Found        bool
	ResolverUsed string
}

type SOALookupResult struct {
	Name          string
	PrimaryNS     string
	Found         bool
	Authoritative bool
	Rcode         int
	ResolverUsed  string
}

type Resolver interface {
	ResolveCNAME(ctx context.Context, host string, maxDepth int) (CNAMELookupResult, error)
	LookupTXT(ctx context.Context, name string) (TXTLookupResult, error)
	LookupNS(ctx context.Context, name string) (NSLookupResult, error)
	LookupSOA(ctx context.Context, name string) (SOALookupResult, error)
	LookupSOAAtServer(ctx context.Context, name, server string) (SOALookupResult, error)
}

type LookupError struct {
	Name         string
	Type         uint16
	ResolverUsed string
	Kind         error
	Err          error
}

func (e *LookupError) Error() string {
	if e == nil {
		return ""
	}
	typeName := dns.TypeToString[e.Type]
	if e.Err == nil {
		return fmt.Sprintf("%s lookup failed for %s via %s: %v", typeName, e.Name, e.ResolverUsed, e.Kind)
	}
	return fmt.Sprintf("%s lookup failed for %s via %s: %v: %v", typeName, e.Name, e.ResolverUsed, e.Kind, e.Err)
}

func (e *LookupError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.Err != nil {
		return e.Err
	}
	return e.Kind
}

func IsNoData(err error) bool {
	return errors.Is(err, ErrNoData)
}

func IsNXDOMAIN(err error) bool {
	return errors.Is(err, ErrNXDOMAIN)
}

type Config struct {
	Resolvers      []string
	Timeout        time.Duration
	Retries        int
	BackoffInitial time.Duration
	BackoffMax     time.Duration
	Rate           float64
}

type DNSResolver struct {
	resolvers  []string
	timeout    time.Duration
	retries    int
	backoff0   time.Duration
	backoffMax time.Duration
	udpClient  *dns.Client
	tcpClient  *dns.Client
	limiter    *rate.Limiter
	next       atomic.Uint64
}

func New(cfg Config) (*DNSResolver, error) {
	resolvers := cfg.Resolvers
	if len(resolvers) == 0 {
		var err error
		resolvers, err = defaultResolvers()
		if err != nil {
			return nil, err
		}
	}
	for i := range resolvers {
		resolvers[i] = normalizeResolver(resolvers[i])
	}
	if len(resolvers) == 0 {
		return nil, ErrNoResolvers
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	backoff0 := cfg.BackoffInitial
	if backoff0 <= 0 {
		backoff0 = 100 * time.Millisecond
	}
	backoffMax := cfg.BackoffMax
	if backoffMax <= 0 {
		backoffMax = 2 * time.Second
	}

	r := &DNSResolver{
		resolvers:  resolvers,
		timeout:    timeout,
		retries:    cfg.Retries,
		backoff0:   backoff0,
		backoffMax: backoffMax,
		udpClient:  &dns.Client{Net: "udp", Timeout: timeout},
		tcpClient:  &dns.Client{Net: "tcp", Timeout: timeout},
	}
	if cfg.Rate > 0 {
		r.limiter = rate.NewLimiter(rate.Limit(cfg.Rate), 1)
	}
	return r, nil
}

func (r *DNSResolver) ResolveCNAME(ctx context.Context, host string, maxDepth int) (CNAMELookupResult, error) {
	if maxDepth <= 0 {
		maxDepth = 8
	}
	current := normalizeName(host)
	if current == "" {
		return CNAMELookupResult{}, &LookupError{Name: host, Type: dns.TypeCNAME, Kind: fmt.Errorf("empty host")}
	}

	seen := map[string]struct{}{current: {}}
	depth := 0
	lastResolver := ""
	chain := []string{current}

	for depth = 0; depth < maxDepth; depth++ {
		answers, resolverUsed, err := r.lookup(ctx, current, dns.TypeCNAME)
		lastResolver = resolverUsed
		if err != nil {
			if depth == 0 && IsNoData(err) {
				return CNAMELookupResult{Found: false, ResolverUsed: resolverUsed}, nil
			}
			if depth > 0 && IsNoData(err) {
				return CNAMELookupResult{
					Found:        true,
					FinalName:    current,
					Chain:        slicesClone(chain),
					ResolverUsed: resolverUsed,
					Depth:        depth,
				}, nil
			}
			return CNAMELookupResult{}, err
		}

		targets := make([]string, 0, len(answers))
		for _, answer := range answers {
			if rr, ok := answer.(*dns.CNAME); ok {
				targets = append(targets, normalizeName(rr.Target))
			}
		}
		if len(targets) > 1 {
			sort.Strings(targets)
		}
		target := ""
		if len(targets) > 0 {
			target = targets[0]
		}
		if target == "" {
			if depth == 0 {
				return CNAMELookupResult{Found: false, ResolverUsed: resolverUsed}, nil
			}
			return CNAMELookupResult{
				Found:        true,
				FinalName:    current,
				Chain:        slicesClone(chain),
				ResolverUsed: resolverUsed,
				Depth:        depth,
			}, nil
		}
		if _, ok := seen[target]; ok {
			return CNAMELookupResult{}, &LookupError{
				Name:         current,
				Type:         dns.TypeCNAME,
				ResolverUsed: resolverUsed,
				Kind:         ErrCNAMELoop,
			}
		}
		seen[target] = struct{}{}
		current = target
		chain = append(chain, current)
	}

	return CNAMELookupResult{}, &LookupError{
		Name:         current,
		Type:         dns.TypeCNAME,
		ResolverUsed: lastResolver,
		Kind:         ErrMaxDepth,
	}
}

func (r *DNSResolver) LookupTXT(ctx context.Context, name string) (TXTLookupResult, error) {
	name = normalizeName(name)
	answers, resolverUsed, err := r.lookup(ctx, name, dns.TypeTXT)
	if err != nil {
		if IsNoData(err) || IsNXDOMAIN(err) {
			return TXTLookupResult{Name: name, ResolverUsed: resolverUsed, Found: false}, nil
		}
		return TXTLookupResult{}, err
	}

	var values []string
	for _, answer := range answers {
		if rr, ok := answer.(*dns.TXT); ok {
			values = append(values, rr.Txt...)
		}
	}

	return TXTLookupResult{
		Name:         name,
		Values:       values,
		Found:        len(values) > 0,
		ResolverUsed: resolverUsed,
	}, nil
}

func (r *DNSResolver) LookupNS(ctx context.Context, name string) (NSLookupResult, error) {
	name = normalizeName(name)
	answers, resolverUsed, err := r.lookup(ctx, name, dns.TypeNS)
	if err != nil {
		if IsNoData(err) || IsNXDOMAIN(err) {
			return NSLookupResult{Name: name, ResolverUsed: resolverUsed, Found: false}, nil
		}
		return NSLookupResult{}, err
	}

	nameservers := make([]string, 0, len(answers))
	for _, answer := range answers {
		if rr, ok := answer.(*dns.NS); ok {
			nameservers = append(nameservers, normalizeName(rr.Ns))
		}
	}
	sort.Strings(nameservers)

	return NSLookupResult{
		Name:         name,
		Nameservers:  nameservers,
		Found:        len(nameservers) > 0,
		ResolverUsed: resolverUsed,
	}, nil
}

func (r *DNSResolver) LookupSOA(ctx context.Context, name string) (SOALookupResult, error) {
	name = normalizeName(name)
	answers, resolverUsed, err := r.lookup(ctx, name, dns.TypeSOA)
	if err != nil {
		if IsNoData(err) || IsNXDOMAIN(err) {
			return SOALookupResult{Name: name, ResolverUsed: resolverUsed, Found: false}, nil
		}
		return SOALookupResult{}, err
	}
	return soaFromAnswers(name, resolverUsed, dns.RcodeSuccess, false, answers), nil
}

func (r *DNSResolver) LookupSOAAtServer(ctx context.Context, name, server string) (SOALookupResult, error) {
	name = normalizeName(name)
	server = normalizeResolver(server)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeSOA)
	msg.RecursionDesired = false

	resp, _, err := r.udpClient.ExchangeContext(ctx, msg, server)
	if err == nil && resp != nil && resp.Truncated {
		resp, _, err = r.tcpClient.ExchangeContext(ctx, msg, server)
	}
	if err != nil {
		return SOALookupResult{}, &LookupError{
			Name:         name,
			Type:         dns.TypeSOA,
			ResolverUsed: server,
			Kind:         classifyTransportError(err),
			Err:          err,
		}
	}
	if resp == nil {
		return SOALookupResult{}, &LookupError{
			Name:         name,
			Type:         dns.TypeSOA,
			ResolverUsed: server,
			Kind:         errors.New("empty dns response"),
		}
	}

	result := soaFromAnswers(name, server, resp.Rcode, resp.Authoritative, resp.Answer)
	return result, nil
}

func (r *DNSResolver) lookup(ctx context.Context, name string, qtype uint16) ([]dns.RR, string, error) {
	if len(r.resolvers) == 0 {
		return nil, "", ErrNoResolvers
	}

	attempts := r.retries + 1
	backoff := r.backoff0
	var lastErr error
	var lastResolver string

	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, lastResolver, err
		}
		resolver := r.pickResolver()
		lastResolver = resolver
		if r.limiter != nil {
			if err := r.limiter.Wait(ctx); err != nil {
				return nil, resolver, err
			}
		}

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), qtype)
		msg.RecursionDesired = true

		resp, _, err := r.udpClient.ExchangeContext(ctx, msg, resolver)
		if err == nil && resp != nil && resp.Truncated {
			resp, _, err = r.tcpClient.ExchangeContext(ctx, msg, resolver)
		}
		if err != nil {
			lastErr = &LookupError{
				Name:         name,
				Type:         qtype,
				ResolverUsed: resolver,
				Kind:         classifyTransportError(err),
				Err:          err,
			}
			if attempt < attempts-1 && isRetryable(lastErr) {
				if err := sleepContext(ctx, backoff); err != nil {
					return nil, resolver, err
				}
				backoff = minDuration(backoff*2, r.backoffMax)
				continue
			}
			return nil, resolver, lastErr
		}
		if resp == nil {
			lastErr = &LookupError{
				Name:         name,
				Type:         qtype,
				ResolverUsed: resolver,
				Kind:         errors.New("empty dns response"),
			}
			if attempt < attempts-1 {
				if err := sleepContext(ctx, backoff); err != nil {
					return nil, resolver, err
				}
				backoff = minDuration(backoff*2, r.backoffMax)
				continue
			}
			return nil, resolver, lastErr
		}

		switch resp.Rcode {
		case dns.RcodeSuccess:
			if len(resp.Answer) == 0 {
				return nil, resolver, &LookupError{
					Name:         name,
					Type:         qtype,
					ResolverUsed: resolver,
					Kind:         ErrNoData,
				}
			}
			return resp.Answer, resolver, nil
		case dns.RcodeNameError:
			return nil, resolver, &LookupError{
				Name:         name,
				Type:         qtype,
				ResolverUsed: resolver,
				Kind:         ErrNXDOMAIN,
			}
		case dns.RcodeServerFailure, dns.RcodeRefused:
			lastErr = &LookupError{
				Name:         name,
				Type:         qtype,
				ResolverUsed: resolver,
				Kind:         fmt.Errorf("dns rcode %s", dns.RcodeToString[resp.Rcode]),
			}
			if attempt < attempts-1 {
				if err := sleepContext(ctx, backoff); err != nil {
					return nil, resolver, err
				}
				backoff = minDuration(backoff*2, r.backoffMax)
				continue
			}
			return nil, resolver, lastErr
		default:
			return nil, resolver, &LookupError{
				Name:         name,
				Type:         qtype,
				ResolverUsed: resolver,
				Kind:         fmt.Errorf("dns rcode %s", dns.RcodeToString[resp.Rcode]),
			}
		}
	}

	return nil, lastResolver, lastErr
}

func (r *DNSResolver) pickResolver() string {
	idx := r.next.Add(1)
	return r.resolvers[(idx-1)%uint64(len(r.resolvers))]
}

func ReadResolversFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, normalizeResolver(line))
	}
	if len(out) == 0 {
		return nil, ErrNoResolvers
	}
	return out, nil
}

func defaultResolvers() ([]string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	if cfg == nil || len(cfg.Servers) == 0 {
		return nil, ErrNoResolvers
	}
	resolvers := make([]string, 0, len(cfg.Servers))
	for _, server := range cfg.Servers {
		resolvers = append(resolvers, net.JoinHostPort(server, cfg.Port))
	}
	return resolvers, nil
}

func normalizeResolver(resolver string) string {
	resolver = strings.TrimSpace(resolver)
	if resolver == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(resolver); err == nil {
		return resolver
	}
	return net.JoinHostPort(resolver, "53")
}

func normalizeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

func soaFromAnswers(name, resolverUsed string, rcode int, authoritative bool, answers []dns.RR) SOALookupResult {
	result := SOALookupResult{
		Name:          name,
		ResolverUsed:  resolverUsed,
		Rcode:         rcode,
		Authoritative: authoritative,
	}
	for _, answer := range answers {
		if rr, ok := answer.(*dns.SOA); ok {
			result.Found = true
			result.PrimaryNS = normalizeName(rr.Ns)
			break
		}
	}
	return result
}

func slicesClone(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func classifyTransportError(err error) error {
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var lookupErr *LookupError
	if errors.As(err, &lookupErr) {
		if errors.Is(lookupErr.Kind, ErrNoData) || errors.Is(lookupErr.Kind, ErrNXDOMAIN) {
			return false
		}
		if strings.Contains(strings.ToLower(lookupErr.Error()), "servfail") || strings.Contains(strings.ToLower(lookupErr.Error()), "refused") {
			return true
		}
	}
	return true
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
