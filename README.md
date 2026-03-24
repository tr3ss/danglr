# danglr

`danglr` is a production-oriented Go CLI for large-scale DNS scanning of subdomain-takeover-related provider patterns defined in `providers.yaml`.

This release keeps GitHub Pages support and adds:

- GitHub Pages
- Azure App Service
- AWS S3 website endpoints
- Netlify
- AWS Route 53 orphaned delegation checks
- Azure DNS orphaned delegation checks
- Cloudflare orphaned delegation checks

Firebase and Vercel are intentionally excluded. Their onboarding flow requires domain verification, so they are not meaningful candidates for this scanner’s current model.

## What Changed

The scanner is now rule-driven instead of hardcoded for one provider.

- Provider definitions live in [`providers.yaml`](./providers.yaml)
- Matching, extraction, TXT verification, inheritance, and finding classification are driven by YAML
- The Go code supplies a small set of built-in primitives and a generic execution engine

## Provider Classes

The engine supports three provider classes.

- `strong-signal`
  Deterministic DNS-side protection logic exists. Current examples: GitHub Pages, Azure App Service.
- `legacy-dangling`
  No protective TXT model is used. Findings are based on legacy/dangling target patterns and should not be overstated. Current example: AWS S3 website endpoints.
- `heuristic`
  DNS alone is not enough for deterministic vulnerability claims. Emit low-confidence findings for manual review. Current example: Netlify.

## Detection Modes

- `txt-protection`
  Match provider target, derive TXT names from templates, query TXT, and classify as `protected` or `unprotected`.
- `claimable-target`
  Match provider target and emit a finding based on dangling or claimable target patterns.
- `platform-heuristic`
  Match provider infrastructure targets and emit a manual-validation finding only.
- `orphaned-delegation`
  Match delegated nameserver providers, then query the delegated nameservers directly for `SOA` to detect likely missing or unprovisioned child zones.

## Current Providers

- `github-pages`
  Matches `*.github.io`, extracts the label immediately before `github.io`, and checks `_github-pages-challenge-{{owner}}.{{host}}` plus inherited parent checks.
- `azure-app-service`
  Matches `azurewebsites.net`, `trafficmanager.net`, and `cloudapp.net`, then checks `asuid.{{host}}`.
- `aws-s3-website`
  Matches legacy S3 website endpoint patterns and emits `likely-dangling-s3` findings.
- `netlify`
  Matches `netlify.app` and emits `netlify-manual-validation` findings only.
- `aws-route53-delegation`
  Matches Route 53 nameserver patterns and emits `likely-orphaned-route53-delegation` findings after recursive NS plus direct SOA validation.
- `azure-dns-delegation`
  Matches Azure DNS nameserver patterns and emits `likely-orphaned-azure-dns-delegation` findings after recursive NS plus direct SOA validation.
- `cloudflare-delegation`
  Matches Cloudflare standard nameservers and Foundation DNS nameservers, then emits `likely-orphaned-cloudflare-delegation` findings after recursive NS plus direct SOA validation.

## Output Model

The scanner no longer forces every provider into `protected` or `unprotected`.

### Protected / Unprotected

These are only used for `txt-protection` providers.

- `protected`
  The provider matched and the configured TXT protection signal was found.
- `unprotected`
  The provider matched and the configured TXT protection signal was not found.

### Findings

These are used for `legacy-dangling` and `heuristic` providers.

- `likely-dangling`
  A provider pattern associated with dangling infrastructure matched.
- `manual-validation-required`
  The match is intentionally not treated as deterministic from DNS alone.

Netlify and S3 findings are routed to `findings.jsonl`, not `protected.jsonl` or `unprotected.jsonl`.
Delegation findings also go to `findings.jsonl`.

## Files Produced

- `protected.jsonl`
- `unprotected.jsonl`
- `findings.jsonl`
- `errors.jsonl`

The CLI also prints a concise summary to stdout.

## Example Output

Example `protected.jsonl` record:

```json
{
  "host": "blog.example.com",
  "provider": "github-pages",
  "class": "strong-signal",
  "detection_mode": "txt-protection",
  "matched_target": "octocat.github.io",
  "final_cname": "octocat.github.io",
  "owner": "octocat",
  "checked_txt_names": [
    "_github-pages-challenge-octocat.blog.example.com",
    "_github-pages-challenge-octocat.example.com"
  ],
  "txt_hits": [
    "_github-pages-challenge-octocat.example.com"
  ],
  "protection_reason": "TXT exists at _github-pages-challenge-octocat.example.com",
  "detection_reason": "cname suffix matched github.io; owner extracted from label before github.io; checked TXT template _github-pages-challenge-{{owner}}.{{host}}; checked TXT template _github-pages-challenge-{{owner}}.{{parent}}",
  "resolver_used": "1.1.1.1:53",
  "status": "protected",
  "severity": "medium",
  "confidence": "high",
  "tags": ["dns", "github", "pages", "sto"],
  "manual_validation_required": false
}
```

Example `findings.jsonl` record:

```json
{
  "host": "static.example.com",
  "provider": "aws-s3-website",
  "class": "legacy-dangling",
  "detection_mode": "claimable-target",
  "matched_target": "bucket.s3-website-us-east-1.amazonaws.com",
  "final_cname": "bucket.s3-website-us-east-1.amazonaws.com",
  "finding_type": "likely-dangling-s3",
  "evidence": ["matched target bucket.s3-website-us-east-1.amazonaws.com"],
  "detection_reason": "cname matched regex (^|\\.)s3-website[.-][a-z0-9-]+\\.amazonaws\\.com\\.?$",
  "resolver_used": "1.1.1.1:53",
  "status": "finding",
  "severity": "medium",
  "confidence": "medium",
  "tags": ["dns", "aws", "s3", "sto", "legacy"],
  "manual_validation_required": true
}
```

Example orphaned delegation finding:

```json
{
  "host": "child.example.com",
  "provider": "aws-route53-delegation",
  "class": "legacy-dangling",
  "detection_mode": "orphaned-delegation",
  "matched_target": "child.example.com",
  "final_cname": "",
  "finding_type": "likely-orphaned-route53-delegation",
  "evidence": [
    "delegated zone child.example.com",
    "recursive NS for child.example.com: ns-123.awsdns-45.com, ns-234.awsdns-56.net",
    "SOA @ ns-123.awsdns-45.com => rcode=REFUSED authoritative=false found=false"
  ],
  "detection_reason": "delegation NS matched regex (^|\\.)ns-[0-9]+\\.awsdns-[0-9]+\\.(com|net|org)\\.?$",
  "resolver_used": "ns-123.awsdns-45.com:53",
  "status": "finding",
  "severity": "high",
  "confidence": "medium",
  "tags": ["dns", "ns", "delegation", "aws", "route53", "sto"],
  "manual_validation_required": true
}
```

## providers.yaml

Provider definitions are human-editable. A provider can define:

- name
- enabled
- class
- detection mode
- confidence and severity
- target suffixes or regexes
- extraction type
- verification templates and inheritance
- dangling or heuristic classification
- delegation classification
- notes and tags

The supported built-in primitives are intentionally small:

- extraction types:
  `none`, `label_before_suffix`, `regex_capture`
- verification methods:
  `txt_exists`, `txt_value_regex`, `txt_exists_or_value_regex`
- dangling methods:
  `dns-target-pattern-only`, `dns-target-plus-weak-indicator`
- heuristic methods:
  `provider-target-only`
- delegation methods:
  `parent-delegation-with-missing-zone`

This is a pragmatic rule engine, not a DSL.

## Template Variables

Supported template variables:

- `{{host}}`
- `{{parent}}`
- `{{parents[n]}}`
- `{{apex}}`
- `{{owner}}`
- `{{target}}`
- `{{label_before_suffix}}`

If a template uses `{{parent}}`, the engine expands it across inherited parent levels up to `max_parent_levels`.

For `a.b.example.com`, the parents are:

- `b.example.com`
- `example.com`

## TXT Verification Guidance

Use `txt_exists` when record existence alone is the relevant protection signal.

- GitHub Pages
- Azure App Service

Use `txt_value_regex` when a provider requires specific TXT contents to be considered protective.

Use `txt_exists_or_value_regex` when either record existence or specific value content should count.

The current bundled providers rely on TXT existence only.

## Build

```bash
go build ./cmd/danglr
```

Or explicitly name the binary:

```bash
go build -o danglr ./cmd/danglr
```

## Usage

Basic scan:

```bash
./danglr -input hosts.txt
```

Use a custom providers file:

```bash
./danglr -input hosts.txt -providers-config providers.yaml
```

Scan only selected providers:

```bash
./danglr -input hosts.txt -provider github-pages,azure-app-service
```

List enabled providers:

```bash
./danglr -list-providers
```

Dump the effective config after allowlist filtering:

```bash
./danglr -provider github-pages,netlify -dump-effective-config
```

High-throughput example:

```bash
./danglr \
  -input hosts.txt \
  -providers-config providers.yaml \
  -resolvers resolvers.txt \
  -untrusted-resolvers untrusted-resolvers.txt \
  -concurrency 500 \
  -rate 2000 \
  -timeout 3s \
  -retries 2 \
  -max-cname-depth 8
```

## Flags

- `-input`
- `-resolvers`
- `-providers-config`
- `-provider`
- `-list-providers`
- `-strict-config`
- `-dump-effective-config`
- `-untrusted-resolvers`
- `-concurrency`
- `-rate`
- `-timeout`
- `-retries`
- `-max-cname-depth`
- `-protected-out`
- `-unprotected-out`
- `-findings-out`
- `-errors-out`
- `-json-summary`
- `-verbose`

## How To Add A New Provider Safely

1. Start with the correct provider class.
2. Choose the narrowest detection mode that matches the provider’s actual onboarding and protection semantics.
3. Prefer suffix matching over broad regexes when possible.
4. Only use `txt-protection` when the provider really has a deterministic DNS-side protection signal.
5. Use `orphaned-delegation` only for providers where recursive NS delegation plus direct authoritative SOA checks are a meaningful signal.
6. Keep `legacy-dangling`, `heuristic`, and `orphaned-delegation` providers marked for manual validation unless you have strong provider-specific evidence otherwise.
7. Validate the rule with `-strict-config` and add tests for the new provider before using it broadly.

## Architecture

Generic parts:

- DNS resolution with retries, resolver rotation, rate limiting, and safe CNAME following
- YAML loading and validation
- domain normalization, parent derivation, and apex derivation
- target suffix and regex matching
- delegated nameserver suffix and regex matching
- Cloudflare standard and Foundation DNS branded nameserver matching
- TXT template rendering and inheritance expansion
- global TXT cache and deduplication
- global NS cache and deduplication for recursive delegation lookups
- two-phase discovery and validation with optional untrusted resolvers
- concurrent engine and JSONL output routing

Intentionally built-in parts:

- the small set of extraction, verification, dangling, and heuristic primitives
- DNS transport behavior and retry policy
- output schemas and routing rules

Provider-specific data lives in YAML. Provider-specific code should only be added when a provider cannot be expressed cleanly with the existing primitives.

## Limitations

- The engine is currently CNAME-focused.
- The engine also supports NS-based orphaned delegation checks.
- Apex `A`/`AAAA` takeover models are not handled in this release.
- Legacy-dangling and heuristic findings are intentionally conservative and should not be treated as confirmed exploitable issues from DNS alone.
- Orphaned delegation findings are intentionally conservative and require manual validation because provider-side zone creation behavior and delegation state still matter.
- Cloudflare custom nameservers are intentionally not matched because they are arbitrary customer-controlled hostnames and are not reliably attributable from DNS name patterns alone.
- `{{apex}}` uses public suffix logic and may be empty for unusual inputs.
- Multiple providers can match the same host and produce multiple records.

## Performance Notes

- Input is streamed.
- Output is streamed as JSONL.
- TXT lookups are globally cached and deduplicated across providers and hosts.
- Recursive NS lookups are globally cached and deduplicated across providers and hosts.
- Worker concurrency is configurable.
- DNS query rate limiting and retries are configurable.
- If `-untrusted-resolvers` is set, broad discovery uses that resolver pool, while final classification uses the trusted resolver pool from `-resolvers` or the system resolver configuration.

## Verification

The current codebase includes unit tests for:

- YAML loading and validation
- suffix and regex matching
- GitHub-style owner extraction
- parent derivation
- template rendering
- TXT decision modes
- inheritance behavior
- multi-provider routing
- TXT cache deduplication
- finding classification
- orphaned delegation classification
- trusted-validation behavior when untrusted discovery resolvers are enabled
- fixture-style integration using a sample `providers.yaml`
