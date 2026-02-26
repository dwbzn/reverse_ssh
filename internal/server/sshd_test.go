package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestRoleAllowed(t *testing.T) {
	allowed := map[string]bool{
		roleClient: true,
		roleProxy:  true,
	}

	if !roleAllowed(allowed, roleClient) {
		t.Fatalf("client role should be allowed")
	}
	if roleAllowed(allowed, roleUser) {
		t.Fatalf("user role should be rejected")
	}
	if !roleAllowed(nil, roleUser) {
		t.Fatalf("nil filter should allow all roles")
	}
}

func TestIsClosedListenerError(t *testing.T) {
	if !isClosedListenerError(net.ErrClosed) {
		t.Fatalf("net.ErrClosed should be treated as a closed listener")
	}

	if !isClosedListenerError(errors.New("use of closed network connection")) {
		t.Fatalf("closed network connection text should be treated as a closed listener")
	}

	if isClosedListenerError(errors.New("temporary listener failure")) {
		t.Fatalf("non-closed errors should not be treated as closed listener errors")
	}
}

func TestCheckAuthWithSourceTrustRejectsSourceRestrictedKeyWhenSourceUntrusted(t *testing.T) {
	pub := generateTestPublicKey(t)

	keysPath := filepath.Join(t.TempDir(), "authorized_controllee_keys")
	line := "from=\"10.0.0.0/8\" " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " test\n"
	if err := os.WriteFile(keysPath, []byte(line), 0600); err != nil {
		t.Fatalf("failed to write temporary key file: %v", err)
	}

	_, err := CheckAuthWithSourceTrust(keysPath, pub, nil, false, false)
	if err == nil {
		t.Fatalf("expected source-trust validation error")
	}
	if !strings.Contains(err.Error(), "cannot be evaluated") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckAuthWithSourceTrustAllowsUnrestrictedKeyWhenSourceUntrusted(t *testing.T) {
	pub := generateTestPublicKey(t)

	keysPath := filepath.Join(t.TempDir(), "authorized_controllee_keys")
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " test\n"
	if err := os.WriteFile(keysPath, []byte(line), 0600); err != nil {
		t.Fatalf("failed to write temporary key file: %v", err)
	}

	_, err := CheckAuthWithSourceTrust(keysPath, pub, nil, false, false)
	if err != nil {
		t.Fatalf("unexpected auth failure: %v", err)
	}
}

func TestParseAddressIPv4Literal(t *testing.T) {
	cidrs, err := ParseAddress("10.12.13.14")
	if err != nil {
		t.Fatalf("ParseAddress() error = %v", err)
	}
	if len(cidrs) != 1 {
		t.Fatalf("expected one cidr, got %d", len(cidrs))
	}

	want := net.ParseIP("10.12.13.14")
	if !cidrs[0].Contains(want) {
		t.Fatalf("cidr %s does not contain %s", cidrs[0].String(), want)
	}

	ones, bits := cidrs[0].Mask.Size()
	if ones != 32 || bits != 32 {
		t.Fatalf("unexpected ipv4 mask size %d/%d", ones, bits)
	}
}

func TestParseAddressIPv6Literal(t *testing.T) {
	cidrs, err := ParseAddress("2001:db8::1")
	if err != nil {
		t.Fatalf("ParseAddress() error = %v", err)
	}
	if len(cidrs) != 1 {
		t.Fatalf("expected one cidr, got %d", len(cidrs))
	}

	want := net.ParseIP("2001:db8::1")
	if !cidrs[0].Contains(want) {
		t.Fatalf("cidr %s does not contain %s", cidrs[0].String(), want)
	}

	ones, bits := cidrs[0].Mask.Size()
	if ones != 128 || bits != 128 {
		t.Fatalf("unexpected ipv6 mask size %d/%d", ones, bits)
	}
}

func generateTestPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer from test key: %v", err)
	}

	return signer.PublicKey()
}
