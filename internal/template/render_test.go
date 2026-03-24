package templateutil

import "testing"

func TestRender(t *testing.T) {
	got, err := Render("_github-pages-challenge-{{owner}}.{{host}}", Context{
		Host:  "blog.example.com",
		Owner: "octocat",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "_github-pages-challenge-octocat.blog.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestValidateRejectsUnknownToken(t *testing.T) {
	if err := Validate("{{unknown}}"); err == nil {
		t.Fatalf("expected error")
	}
}
