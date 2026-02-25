package nat

import (
	"bytes"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	tok := &Token{
		Version:         TokenVersionV1,
		PreferredRegion: 42,
		DirectAddr:      "127.0.0.1:3232",
	}
	for i := range tok.ServerDirectPublicKey {
		tok.ServerDirectPublicKey[i] = byte(i)
		tok.ServerDERPPublicKey[i] = byte(i + 7)
	}

	encoded, err := tok.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	decoded, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("DecodeToken() error = %v", err)
	}

	if decoded.Version != tok.Version {
		t.Fatalf("decoded version = %d, want %d", decoded.Version, tok.Version)
	}
	if decoded.PreferredRegion != tok.PreferredRegion {
		t.Fatalf("decoded preferred region = %d, want %d", decoded.PreferredRegion, tok.PreferredRegion)
	}
	if decoded.DirectAddr != tok.DirectAddr {
		t.Fatalf("decoded direct addr = %q, want %q", decoded.DirectAddr, tok.DirectAddr)
	}
	if !bytes.Equal(decoded.ServerDirectPublicKey[:], tok.ServerDirectPublicKey[:]) {
		t.Fatalf("decoded direct public key mismatch")
	}
	if !bytes.Equal(decoded.ServerDERPPublicKey[:], tok.ServerDERPPublicKey[:]) {
		t.Fatalf("decoded derp public key mismatch")
	}
}

func TestParseDestinationRejectsNonOpaqueToken(t *testing.T) {
	_, err := ParseDestination("nat://abc/def")
	if err == nil {
		t.Fatalf("ParseDestination should reject token with path")
	}
}

func TestDeriveIdentityDeterministic(t *testing.T) {
	privA, pubA, err := DeriveIdentity([]byte("host-private-key-A"))
	if err != nil {
		t.Fatalf("DeriveIdentity() error = %v", err)
	}
	privB, pubB, err := DeriveIdentity([]byte("host-private-key-A"))
	if err != nil {
		t.Fatalf("DeriveIdentity() second call error = %v", err)
	}
	if !bytes.Equal(privA, privB) {
		t.Fatalf("private key derivation is not deterministic")
	}
	if !bytes.Equal(pubA[:], pubB[:]) {
		t.Fatalf("public key derivation is not deterministic")
	}
}

func TestDeriveDERPIdentityDeterministic(t *testing.T) {
	privA, pubA, err := DeriveDERPIdentity([]byte("host-private-key-A"))
	if err != nil {
		t.Fatalf("DeriveDERPIdentity() error = %v", err)
	}
	privB, pubB, err := DeriveDERPIdentity([]byte("host-private-key-A"))
	if err != nil {
		t.Fatalf("DeriveDERPIdentity() second call error = %v", err)
	}
	if !bytes.Equal(privA[:], privB[:]) {
		t.Fatalf("private key derivation is not deterministic")
	}
	if !bytes.Equal(pubA[:], pubB[:]) {
		t.Fatalf("public key derivation is not deterministic")
	}
}
