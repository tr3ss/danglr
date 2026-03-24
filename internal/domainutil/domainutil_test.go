package domainutil

import "testing"

func TestParentDomains(t *testing.T) {
	got := ParentDomains("A.B.Example.com.", 3)
	want := []string{"b.example.com", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestLabelBeforeSuffix(t *testing.T) {
	got, err := LabelBeforeSuffix("foo.bar.github.io.", "github.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "bar" {
		t.Fatalf("got %q want %q", got, "bar")
	}
}
