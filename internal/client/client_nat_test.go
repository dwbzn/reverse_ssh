package client

import (
	"testing"

	"github.com/NHAS/reverse_ssh/internal/nat"
)

func TestDetermineConnectionTypeNAT(t *testing.T) {
	addr, scheme := determineConnectionType("nat://exampletoken")
	if scheme != nat.Scheme {
		t.Fatalf("scheme = %q, want %q", scheme, nat.Scheme)
	}
	if addr != "exampletoken" {
		t.Fatalf("addr = %q, want %q", addr, "exampletoken")
	}
}
