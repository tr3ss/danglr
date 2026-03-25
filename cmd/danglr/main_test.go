package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenOutputWritersUnprotectedOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := cliConfig{
		protectedOut:    filepath.Join(dir, "protected.jsonl"),
		unprotectedOut:  filepath.Join(dir, "unprotected.jsonl"),
		findingsOut:     filepath.Join(dir, "findings.jsonl"),
		errorsOut:       filepath.Join(dir, "errors.jsonl"),
		unprotectedOnly: true,
	}

	protectedWriter, unprotectedWriter, findingsWriter, errorsWriter, err := openOutputWriters(cfg)
	if err != nil {
		t.Fatalf("openOutputWriters returned error: %v", err)
	}
	defer protectedWriter.Close()
	defer unprotectedWriter.Close()
	defer findingsWriter.Close()
	defer errorsWriter.Close()

	if err := protectedWriter.Write(map[string]string{"status": "protected"}); err != nil {
		t.Fatalf("protected discard writer returned error: %v", err)
	}
	if err := findingsWriter.Write(map[string]string{"status": "finding"}); err != nil {
		t.Fatalf("findings discard writer returned error: %v", err)
	}
	if err := errorsWriter.Write(map[string]string{"status": "error"}); err != nil {
		t.Fatalf("errors discard writer returned error: %v", err)
	}
	if err := unprotectedWriter.Write(map[string]string{"status": "unprotected"}); err != nil {
		t.Fatalf("unprotected writer returned error: %v", err)
	}

	if _, err := os.Stat(cfg.unprotectedOut); err != nil {
		t.Fatalf("expected unprotected output file to exist: %v", err)
	}
	for _, path := range []string{cfg.protectedOut, cfg.findingsOut, cfg.errorsOut} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s not to exist, got err=%v", path, err)
		}
	}
}

func TestOpenOutputWritersFindingsOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := cliConfig{
		protectedOut:   filepath.Join(dir, "protected.jsonl"),
		unprotectedOut: filepath.Join(dir, "unprotected.jsonl"),
		findingsOut:    filepath.Join(dir, "findings.jsonl"),
		errorsOut:      filepath.Join(dir, "errors.jsonl"),
		findingsOnly:   true,
	}

	protectedWriter, unprotectedWriter, findingsWriter, errorsWriter, err := openOutputWriters(cfg)
	if err != nil {
		t.Fatalf("openOutputWriters returned error: %v", err)
	}
	defer protectedWriter.Close()
	defer unprotectedWriter.Close()
	defer findingsWriter.Close()
	defer errorsWriter.Close()

	if err := findingsWriter.Write(map[string]string{"status": "finding"}); err != nil {
		t.Fatalf("findings writer returned error: %v", err)
	}

	if _, err := os.Stat(cfg.findingsOut); err != nil {
		t.Fatalf("expected findings output file to exist: %v", err)
	}
	for _, path := range []string{cfg.protectedOut, cfg.unprotectedOut, cfg.errorsOut} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s not to exist, got err=%v", path, err)
		}
	}
}

func TestValidateOutputMode(t *testing.T) {
	tests := []struct {
		name    string
		cfg     cliConfig
		wantErr bool
	}{
		{
			name:    "stdout requires single stream mode",
			cfg:     cliConfig{stdout: true, noSummary: true},
			wantErr: true,
		},
		{
			name:    "stdout requires no summary",
			cfg:     cliConfig{stdout: true, unprotectedOnly: true},
			wantErr: true,
		},
		{
			name:    "single stream modes are mutually exclusive",
			cfg:     cliConfig{unprotectedOnly: true, findingsOnly: true},
			wantErr: true,
		},
		{
			name:    "valid unprotected stdout mode",
			cfg:     cliConfig{stdout: true, noSummary: true, unprotectedOnly: true},
			wantErr: false,
		},
		{
			name:    "valid findings stdout mode",
			cfg:     cliConfig{stdout: true, noSummary: true, findingsOnly: true},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutputMode(tt.cfg)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
