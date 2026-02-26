package nat

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/nacl/box"
)

const (
	signalDialInit byte = 1
	signalDialAck  byte = 2
	signalData     byte = 3
	signalClose    byte = 4
)

type signalMessage struct {
	Type      byte
	SessionID [16]byte
	Payload   []byte
}

var globalWGCounter atomic.Uint64

func encodeSignalMessage(message signalMessage, privateKey, publicKey [32]byte) []byte {
	// Fake WireGuard Transport Data packet

	innerLen := 1 + 16 + len(message.Payload)
	// We need 2 bytes to store the inner length
	innerPad := 16 - ((innerLen + 2) % 16)
	if innerPad == 16 {
		innerPad = 0
	}

	inner := make([]byte, 0, 2+innerLen+innerPad)
	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], uint16(innerLen))
	inner = append(inner, lenBuf[:]...)
	inner = append(inner, message.Type)
	inner = append(inner, message.SessionID[:]...)
	inner = append(inner, message.Payload...)

	if innerPad > 0 {
		inner = append(inner, make([]byte, innerPad)...)
	}

	counter := globalWGCounter.Add(1)
	var counterBuf [8]byte
	binary.LittleEndian.PutUint64(counterBuf[:], counter)

	var nonce [24]byte
	copy(nonce[:], counterBuf[:])

	encrypted := box.Seal(nil, inner, &nonce, &publicKey, &privateKey)

	outLen := 16 + len(encrypted)
	out := make([]byte, 0, outLen)

	// WG Type 4 (Transport Data)
	out = append(out, 0x04, 0x00, 0x00, 0x00)
	// Fake receiver index (use first 4 bytes of session ID)
	out = append(out, message.SessionID[:4]...)
	out = append(out, counterBuf[:]...)
	out = append(out, encrypted...)

	return out
}

func decodeSignalMessage(raw []byte, privateKey, publicKey [32]byte) (signalMessage, error) {
	var message signalMessage

	if len(raw) == 0 {
		return message, fmt.Errorf("empty signal message")
	}

	// Must be at least 16 (Header) + 16 (MAC) + 2 (Len) + 17 (Min Inner) = 51 bytes
	if len(raw) < 51 {
		return message, fmt.Errorf("signal message too short")
	}

	// Check WG Type 4
	if raw[0] != 0x04 || raw[1] != 0x00 || raw[2] != 0x00 || raw[3] != 0x00 {
		return message, fmt.Errorf("invalid signal message type")
	}

	var nonce [24]byte
	copy(nonce[:], raw[8:16])

	inner, ok := box.Open(nil, raw[16:], &nonce, &publicKey, &privateKey)
	if !ok {
		return message, fmt.Errorf("signal message decryption failed")
	}

	if len(inner) < 19 {
		return message, fmt.Errorf("signal inner message too short")
	}

	innerLen := int(binary.LittleEndian.Uint16(inner[0:2]))
	if innerLen < 17 || 2+innerLen > len(inner) {
		return message, fmt.Errorf("invalid signal inner length")
	}

	payloadRaw := inner[2 : 2+innerLen]

	message.Type = payloadRaw[0]
	copy(message.SessionID[:], payloadRaw[1:17])
	message.Payload = append([]byte(nil), payloadRaw[17:]...)

	return message, nil
}
