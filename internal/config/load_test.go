package config

import "testing"

func TestParseProvidersStrictRejectsUnknownField(t *testing.T) {
	data := []byte(`
providers:
  - name: github-pages
    enabled: true
    class: strong-signal
    detection_mode: txt-protection
    confidence: high
    severity: medium
    extra_field: no
    match:
      dns_record: cname
      target_suffixes: [github.io]
    extraction:
      type: label_before_suffix
      suffix: github.io
    verification:
      method: txt_exists
      txt_templates:
        - "_github-pages-challenge-{{owner}}.{{host}}"
      inheritance:
        enabled: false
        max_parent_levels: 0
      protected_if_any_txt_exists: true
`)
	if _, err := ParseProviders(data, true); err == nil {
		t.Fatalf("expected strict parse error")
	}
}

func TestParseProvidersValidation(t *testing.T) {
	data := []byte(`
providers:
  - enabled: true
    class: strong-signal
    detection_mode: txt-protection
    confidence: high
    severity: medium
    match:
      dns_record: cname
      target_suffixes: [github.io]
    extraction:
      type: none
    verification:
      method: txt_exists
      txt_templates: ["asuid.{{host}}"]
      inheritance:
        enabled: false
        max_parent_levels: 0
      protected_if_any_txt_exists: true
`)
	if _, err := ParseProviders(data, false); err == nil {
		t.Fatalf("expected validation error")
	}
}
