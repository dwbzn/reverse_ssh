package nat

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	Scheme = "ts"

	DestinationPrefix = Scheme + "://"
	TokenVersionV1    = 1
)

var (
	ErrInvalidDestination = errors.New("invalid ts destination")
	ErrInvalidToken       = errors.New("invalid ts token")
)

// Token is the versioned TS destination payload baked into ts:// addresses.
type Token struct {
	Version             uint8
	ServerDERPPublicKey [32]byte
	PreferredRegion     uint16
}

func (t *Token) Validate() error {
	if t.Version != TokenVersionV1 {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidToken, t.Version)
	}

	var zero [32]byte
	if t.ServerDERPPublicKey == zero {
		return fmt.Errorf("%w: missing derp server key", ErrInvalidToken)
	}

	return nil
}

func (t *Token) Encode() (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}

	// version(1) + derp_pub(32) + region(2)
	total := 1 + 32 + 2
	buf := make([]byte, total)
	pos := 0

	buf[pos] = t.Version
	pos++

	copy(buf[pos:pos+32], t.ServerDERPPublicKey[:])
	pos += 32

	binary.BigEndian.PutUint16(buf[pos:pos+2], t.PreferredRegion)

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func DecodeToken(encoded string) (*Token, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("%w: decode failed: %v", ErrInvalidToken, err)
	}

	// version + derp_pub + region
	if len(raw) != 35 {
		return nil, fmt.Errorf("%w: payload length mismatch", ErrInvalidToken)
	}

	t := &Token{}
	pos := 0

	t.Version = raw[pos]
	pos++

	copy(t.ServerDERPPublicKey[:], raw[pos:pos+32])
	pos += 32

	t.PreferredRegion = binary.BigEndian.Uint16(raw[pos : pos+2])

	if err := t.Validate(); err != nil {
		return nil, err
	}
	return t, nil
}

func ParseDestination(destination string) (*Token, error) {
	destination = strings.TrimSpace(destination)
	if !strings.HasPrefix(destination, DestinationPrefix) {
		return nil, fmt.Errorf("%w: expected %q prefix", ErrInvalidDestination, DestinationPrefix)
	}
	tokenRaw := strings.TrimSpace(destination[len(DestinationPrefix):])
	if tokenRaw == "" {
		return nil, fmt.Errorf("%w: missing token payload", ErrInvalidDestination)
	}
	if strings.ContainsAny(tokenRaw, "/?#") {
		return nil, fmt.Errorf("%w: token payload must be opaque", ErrInvalidDestination)
	}
	return DecodeToken(tokenRaw)
}
