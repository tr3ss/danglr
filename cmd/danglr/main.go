package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"danglr/internal/config"
	"danglr/internal/dnsresolver"
	"danglr/internal/engine"
	"danglr/internal/output"
	"danglr/internal/providers"
)

type cliConfig struct {
	inputPath              string
	resolversPath          string
	untrustedResolversPath string
	providersConfigPath    string
	providerAllowlist      string
	listProviders          bool
	strictConfig           bool
	dumpEffectiveConfig    bool
	concurrency            int
	rate                   float64
	timeout                time.Duration
	retries                int
	maxCNAMEDepth          int
	protectedOut           string
	unprotectedOut         string
	findingsOut            string
	errorsOut              string
	unprotectedOnly        bool
	findingsOnly           bool
	stdout                 bool
	noSummary              bool
	jsonSummary            bool
	verbose                bool
}

func main() {
	cfg := parseFlags()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg cliConfig) error {
	if err := validateOutputMode(cfg); err != nil {
		return err
	}

	root, err := config.LoadProviders(cfg.providersConfigPath, cfg.strictConfig)
	if err != nil {
		return fmt.Errorf("load providers config: %w", err)
	}

	allowlist := parseAllowlist(cfg.providerAllowlist)
	if len(allowlist) > 0 {
		root = root.Filter(allowlist)
		if len(root.Providers) == 0 {
			return fmt.Errorf("provider allowlist matched no configured providers")
		}
	}

	if cfg.listProviders {
		printProviders(root.EnabledProviders())
		return nil
	}
	if cfg.dumpEffectiveConfig {
		data, err := config.MarshalProviders(root)
		if err != nil {
			return fmt.Errorf("dump effective config: %w", err)
		}
		_, err = os.Stdout.Write(data)
		return err
	}
	if cfg.inputPath == "" {
		return fmt.Errorf("missing required -input flag")
	}

	inputFile, err := os.Open(cfg.inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inputFile.Close()

	var resolvers []string
	if cfg.resolversPath != "" {
		resolvers, err = dnsresolver.ReadResolversFile(cfg.resolversPath)
		if err != nil {
			return fmt.Errorf("read resolvers file: %w", err)
		}
	}

	validationResolver, err := dnsresolver.New(dnsresolver.Config{
		Resolvers:      resolvers,
		Timeout:        cfg.timeout,
		Retries:        cfg.retries,
		BackoffInitial: 100 * time.Millisecond,
		BackoffMax:     2 * time.Second,
		Rate:           cfg.rate,
	})
	if err != nil {
		return fmt.Errorf("configure validation resolver: %w", err)
	}

	discoveryResolver := validationResolver
	if cfg.untrustedResolversPath != "" {
		untrustedResolvers, err := dnsresolver.ReadResolversFile(cfg.untrustedResolversPath)
		if err != nil {
			return fmt.Errorf("read untrusted resolvers file: %w", err)
		}
		discoveryResolver, err = dnsresolver.New(dnsresolver.Config{
			Resolvers:      untrustedResolvers,
			Timeout:        cfg.timeout,
			Retries:        cfg.retries,
			BackoffInitial: 100 * time.Millisecond,
			BackoffMax:     2 * time.Second,
			Rate:           cfg.rate,
		})
		if err != nil {
			return fmt.Errorf("configure discovery resolver: %w", err)
		}
	}

	protectedWriter, unprotectedWriter, findingsWriter, errorsWriter, err := openOutputWriters(cfg)
	if err != nil {
		return err
	}

	var logger *log.Logger
	if cfg.verbose {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}

	scanEngine := engine.New(engine.Config{
		Concurrency:   cfg.concurrency,
		MaxCNAMEDepth: cfg.maxCNAMEDepth,
		Verbose:       cfg.verbose,
	}, discoveryResolver, validationResolver, root.EnabledProviders(), protectedWriter, unprotectedWriter, findingsWriter, errorsWriter, logger)
	defer scanEngine.Close()

	summary, err := scanEngine.Run(ctx, inputFile)
	if !cfg.noSummary {
		printSummary(summary, cfg.jsonSummary)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("scan interrupted")
	}
	return nil
}

func parseFlags() cliConfig {
	defaultConcurrency := runtime.NumCPU() * 32
	if defaultConcurrency < 64 {
		defaultConcurrency = 64
	}

	cfg := cliConfig{}
	flag.StringVar(&cfg.inputPath, "input", "", "Path to the input file containing one hostname per line.")
	flag.StringVar(&cfg.resolversPath, "resolvers", "", "Optional path to the trusted resolver list used for validation. Each line should be an IP or host, optionally with :port.")
	flag.StringVar(&cfg.untrustedResolversPath, "untrusted-resolvers", "", "Optional path to a larger untrusted resolver list used only for fast discovery before trusted validation.")
	flag.StringVar(&cfg.providersConfigPath, "providers-config", "providers.yaml", "Path to the provider definition YAML file.")
	flag.StringVar(&cfg.providerAllowlist, "provider", "", "Optional comma-separated allowlist of provider names to run.")
	flag.BoolVar(&cfg.listProviders, "list-providers", false, "List enabled providers from the config and exit.")
	flag.BoolVar(&cfg.strictConfig, "strict-config", false, "Fail if providers.yaml contains unknown fields.")
	flag.BoolVar(&cfg.dumpEffectiveConfig, "dump-effective-config", false, "Print the loaded provider configuration after filtering and exit.")
	flag.IntVar(&cfg.concurrency, "concurrency", defaultConcurrency, "Number of concurrent host workers.")
	flag.Float64Var(&cfg.rate, "rate", 500, "Maximum DNS queries per second across all workers. Set to 0 for unlimited.")
	flag.DurationVar(&cfg.timeout, "timeout", 3*time.Second, "Per-DNS-query timeout.")
	flag.IntVar(&cfg.retries, "retries", 2, "Retry count for transient DNS failures.")
	flag.IntVar(&cfg.maxCNAMEDepth, "max-cname-depth", 8, "Maximum CNAME chain depth to follow.")
	flag.StringVar(&cfg.protectedOut, "protected-out", "protected.jsonl", "Path to the protected JSONL output file.")
	flag.StringVar(&cfg.unprotectedOut, "unprotected-out", "unprotected.jsonl", "Path to the unprotected JSONL output file.")
	flag.StringVar(&cfg.findingsOut, "findings-out", "findings.jsonl", "Path to the generalized findings JSONL output file.")
	flag.StringVar(&cfg.errorsOut, "errors-out", "errors.jsonl", "Path to the errors JSONL output file.")
	flag.BoolVar(&cfg.unprotectedOnly, "unprotected-only", false, "Write only unprotected JSONL records and discard protected, findings, and errors output files.")
	flag.BoolVar(&cfg.findingsOnly, "findings-only", false, "Write only findings JSONL records and discard protected, unprotected, and errors output files.")
	flag.BoolVar(&cfg.stdout, "stdout", false, "Write the selected single-stream output to stdout instead of a file. Use with -unprotected-only or -findings-only.")
	flag.BoolVar(&cfg.noSummary, "no-summary", false, "Suppress the final summary output.")
	flag.BoolVar(&cfg.jsonSummary, "json-summary", false, "Print the final summary as JSON instead of text.")
	flag.BoolVar(&cfg.verbose, "verbose", false, "Enable verbose progress logging to stderr.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "danglr scans hostnames against provider-defined subdomain-takeover rules loaded from YAML.\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  danglr -input hosts.txt [flags]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  danglr -list-providers [flags]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  danglr -dump-effective-config [flags]\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Examples:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  danglr -input hosts.txt\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  danglr -input hosts.txt -provider github-pages,azure-app-service\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  danglr -input hosts.txt -providers-config providers.yaml -resolvers resolvers.txt -untrusted-resolvers untrusted-resolvers.txt -concurrency 500 -rate 2000\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  danglr -list-providers -providers-config providers.yaml\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  danglr -input hosts.txt -provider github-pages -unprotected-only -unprotected-out github-unprotected.jsonl\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  danglr -input hosts.txt -findings-only -stdout -no-summary\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	return cfg
}

func printProviders(rules []providers.ProviderRule) {
	for _, rule := range rules {
		fmt.Printf("%s\tclass=%s\tmode=%s\tconfidence=%s\tenabled=%t\n", rule.Name, rule.Class, rule.DetectionMode, rule.Confidence, rule.Enabled)
	}
}

func printSummary(summary output.Summary, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(summary)
		return
	}

	fmt.Printf("total input hosts: %d\n", summary.TotalInputHosts)
	fmt.Printf("provider matches: %d\n", summary.ProviderMatches)
	fmt.Printf("protected: %d\n", summary.Protected)
	fmt.Printf("unprotected: %d\n", summary.Unprotected)
	fmt.Printf("findings: %d\n", summary.Findings)
	fmt.Printf("errors: %d\n", summary.Errors)
}

func parseAllowlist(value string) map[string]struct{} {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	allowlist := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		allowlist[part] = struct{}{}
	}
	return allowlist
}

func openOutputWriters(cfg cliConfig) (output.Writer, output.Writer, output.Writer, output.Writer, error) {
	discard := output.NewDiscardWriter()

	if cfg.unprotectedOnly {
		var unprotectedWriter output.Writer
		var err error
		if cfg.stdout {
			unprotectedWriter = output.NewStdoutWriter()
		} else {
			unprotectedWriter, err = output.NewJSONLWriter(cfg.unprotectedOut)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("open unprotected output: %w", err)
			}
		}
		return discard, unprotectedWriter, discard, discard, nil
	}
	if cfg.findingsOnly {
		var findingsWriter output.Writer
		var err error
		if cfg.stdout {
			findingsWriter = output.NewStdoutWriter()
		} else {
			findingsWriter, err = output.NewJSONLWriter(cfg.findingsOut)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("open findings output: %w", err)
			}
		}
		return discard, discard, findingsWriter, discard, nil
	}

	protectedWriter, err := output.NewJSONLWriter(cfg.protectedOut)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open protected output: %w", err)
	}
	unprotectedWriter, err := output.NewJSONLWriter(cfg.unprotectedOut)
	if err != nil {
		_ = protectedWriter.Close()
		return nil, nil, nil, nil, fmt.Errorf("open unprotected output: %w", err)
	}
	findingsWriter, err := output.NewJSONLWriter(cfg.findingsOut)
	if err != nil {
		_ = protectedWriter.Close()
		_ = unprotectedWriter.Close()
		return nil, nil, nil, nil, fmt.Errorf("open findings output: %w", err)
	}
	errorsWriter, err := output.NewJSONLWriter(cfg.errorsOut)
	if err != nil {
		_ = protectedWriter.Close()
		_ = unprotectedWriter.Close()
		_ = findingsWriter.Close()
		return nil, nil, nil, nil, fmt.Errorf("open errors output: %w", err)
	}

	return protectedWriter, unprotectedWriter, findingsWriter, errorsWriter, nil
}

func validateOutputMode(cfg cliConfig) error {
	if cfg.unprotectedOnly && cfg.findingsOnly {
		return fmt.Errorf("-unprotected-only and -findings-only are mutually exclusive")
	}
	if cfg.stdout && !cfg.unprotectedOnly && !cfg.findingsOnly {
		return fmt.Errorf("-stdout requires either -unprotected-only or -findings-only")
	}
	if cfg.stdout && !cfg.noSummary {
		return fmt.Errorf("-stdout requires -no-summary to keep stdout valid JSONL")
	}
	return nil
}
