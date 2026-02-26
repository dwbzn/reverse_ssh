package nat

import (
	"bytes"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	tok := &Token{
		Version: TokenVersionV1,
	}
	for i := range tok.ServerDERPPublicKey {
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
	if !bytes.Equal(decoded.ServerDERPPublicKey[:], tok.ServerDERPPublicKey[:]) {
		t.Fatalf("decoded derp public key mismatch")
	}
}
