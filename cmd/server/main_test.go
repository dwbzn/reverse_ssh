package main

import (
	"strings"
	"testing"

	"github.com/NHAS/reverse_ssh/internal/terminal"
)

func TestServerFlagsIncludeNAT(t *testing.T) {
	flags := serverValidFlags()
	if !flags["nat"] {
		t.Fatalf("nat flag missing from server flag set")
	}
}

func TestParseLineValidFlagsAcceptsNAT(t *testing.T) {
	line, err := terminal.ParseLineValidFlags("server --nat 127.0.0.1:2222", 0, serverValidFlags())
	if err != nil {
		t.Fatalf("ParseLineValidFlags() error = %v", err)
	}
	if !line.IsSet("nat") {
		t.Fatalf("expected --nat to be set")
	}
	if len(line.Arguments) == 0 {
		t.Fatalf("expected listen address argument")
	}
	if got := strings.TrimSpace(line.Arguments[len(line.Arguments)-1].Value()); got != "127.0.0.1:2222" {
		t.Fatalf("listen address = %q, want %q", got, "127.0.0.1:2222")
	}
}

func TestInferConnectBackAddressKeepsExplicitHost(t *testing.T) {
	got := inferConnectBackAddress("192.0.2.10:3232")
	if got != "192.0.2.10:3232" {
		t.Fatalf("inferConnectBackAddress() = %q, want %q", got, "192.0.2.10:3232")
	}
}

func TestInferConnectBackAddressKeepsExplicitIPv6Host(t *testing.T) {
	got := inferConnectBackAddress("[2001:db8::1]:3232")
	if got != "[2001:db8::1]:3232" {
		t.Fatalf("inferConnectBackAddress() = %q, want %q", got, "[2001:db8::1]:3232")
	}
}

func TestInferConnectBackAddressInvalidInputFallsBack(t *testing.T) {
	const in = "not-an-address"
	got := inferConnectBackAddress(in)
	if got != in {
		t.Fatalf("inferConnectBackAddress() = %q, want %q", got, in)
	}
}

func TestIsUnspecifiedHost(t *testing.T) {
	if !isUnspecifiedHost("") {
		t.Fatalf("empty host should be treated as unspecified")
	}
	if !isUnspecifiedHost("0.0.0.0") {
		t.Fatalf("0.0.0.0 should be treated as unspecified")
	}
	if !isUnspecifiedHost("::") {
		t.Fatalf(":: should be treated as unspecified")
	}
	if isUnspecifiedHost("127.0.0.1") {
		t.Fatalf("127.0.0.1 should not be treated as unspecified")
	}
}
