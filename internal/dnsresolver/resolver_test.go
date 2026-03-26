package dnsresolver

import (
	"testing"

	"github.com/miekg/dns"
)

func TestExtractNameserversFiltersCNAMETargetNS(t *testing.T) {
	answers := []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "play.nintendo.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 600},
			Target: "d1x8dzgwcdoyln.cloudfront.net.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: "d1x8dzgwcdoyln.cloudfront.net.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800},
			Ns:  "ns-1340.awsdns-39.org.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: "d1x8dzgwcdoyln.cloudfront.net.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800},
			Ns:  "ns-847.awsdns-41.net.",
		},
	}

	got := extractNameservers("play.nintendo.com", answers)
	if len(got) != 0 {
		t.Fatalf("expected no nameservers for cname target, got %v", got)
	}
}

func TestExtractNameserversKeepsExactOwnerMatch(t *testing.T) {
	answers := []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: "child.example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800},
			Ns:  "ns-123.awsdns-45.com.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: "child.example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800},
			Ns:  "ns-234.awsdns-56.net.",
		},
	}

	got := extractNameservers("child.example.com", answers)
	if len(got) != 2 {
		t.Fatalf("expected 2 nameservers, got %d (%v)", len(got), got)
	}
	if got[0] != "ns-123.awsdns-45.com" || got[1] != "ns-234.awsdns-56.net" {
		t.Fatalf("unexpected nameservers: %v", got)
	}
}
