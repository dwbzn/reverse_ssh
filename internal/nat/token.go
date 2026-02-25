package nat

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	Scheme = "nat"

	DestinationPrefix = Scheme + "://"
	TokenVersionV1    = 1
)

var (
	ErrInvalidDestination = errors.New("invalid nat destination")
	ErrInvalidToken       = errors.New("invalid nat token")
)

// Token is the versioned NAT destination payload baked into nat:// addresses.
type Token struct {
	Version               uint8
	ServerDirectPublicKey [32]byte
	ServerDERPPublicKey   [32]byte
	PreferredRegion       uint16
	DirectAddr            string
}

func (t *Token) Validate() error {
	if t.Version != TokenVersionV1 {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidToken, t.Version)
	}
	if _, err := net.ResolveUDPAddr("udp", t.DirectAddr); err != nil {
		return fmt.Errorf("%w: invalid direct address: %v", ErrInvalidToken, err)
	}
	var zero [32]byte
	if t.ServerDERPPublicKey == zero {
		return fmt.Errorf("%w: missing derp server key", ErrInvalidToken)
	}
	if t.ServerDirectPublicKey == zero {
		return fmt.Errorf("%w: missing direct server key", ErrInvalidToken)
	}
	return nil
}

func (t *Token) Encode() (string, error) {
	if err := t.Validate(); err != nil {
		return "", err
	}

	if len(t.DirectAddr) > 0xFFFF {
		return "", fmt.Errorf("%w: address too long", ErrInvalidToken)
	}

	// version(1) + direct_pub(32) + derp_pub(32) + region(2) + direct_len(2) + direct_addr
	total := 1 + 32 + 32 + 2 + 2 + len(t.DirectAddr)
	buf := make([]byte, total)
	pos := 0

	buf[pos] = t.Version
	pos++

	copy(buf[pos:pos+32], t.ServerDirectPublicKey[:])
	pos += 32

	copy(buf[pos:pos+32], t.ServerDERPPublicKey[:])
	pos += 32

	binary.BigEndian.PutUint16(buf[pos:pos+2], t.PreferredRegion)
	pos += 2

	binary.BigEndian.PutUint16(buf[pos:pos+2], uint16(len(t.DirectAddr)))
	pos += 2
	copy(buf[pos:pos+len(t.DirectAddr)], t.DirectAddr)

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func DecodeToken(encoded string) (*Token, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("%w: decode failed: %v", ErrInvalidToken, err)
	}

	// version + direct_pub + derp_pub + region + direct_len
	if len(raw) < 69 {
		return nil, fmt.Errorf("%w: payload too short", ErrInvalidToken)
	}

	t := &Token{}
	pos := 0

	t.Version = raw[pos]
	pos++

	copy(t.ServerDirectPublicKey[:], raw[pos:pos+32])
	pos += 32

	copy(t.ServerDERPPublicKey[:], raw[pos:pos+32])
	pos += 32

	t.PreferredRegion = binary.BigEndian.Uint16(raw[pos : pos+2])
	pos += 2

	directLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	if len(raw) != pos+directLen {
		return nil, fmt.Errorf("%w: direct address length mismatch", ErrInvalidToken)
	}
	t.DirectAddr = string(raw[pos : pos+directLen])

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
