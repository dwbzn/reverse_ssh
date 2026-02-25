package nat

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const derpKeyDerivationContext = "reverse_ssh/nat/v1/derp_identity"

func DeriveDERPIdentity(hostPrivateKey []byte) (private [32]byte, public [32]byte, err error) {
	if len(hostPrivateKey) == 0 {
		return private, public, fmt.Errorf("host private key bytes cannot be empty")
	}

	reader := hkdf.New(sha256.New, hostPrivateKey, nil, []byte(derpKeyDerivationContext))
	if _, err := io.ReadFull(reader, private[:]); err != nil {
		return private, public, fmt.Errorf("failed to derive derp key seed: %w", err)
	}

	clampCurve25519Private(private[:])
	curve25519.ScalarBaseMult(&public, &private)
	return private, public, nil
}

func randomDERPIdentity() (private [32]byte, public [32]byte, err error) {
	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		return private, public, err
	}
	clampCurve25519Private(private[:])
	curve25519.ScalarBaseMult(&public, &private)
	return private, public, nil
}

func clampCurve25519Private(k []byte) {
	if len(k) != 32 {
		return
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}
