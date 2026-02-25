package nat

import (
	"encoding/json"
	"fmt"
)

const (
	signalDialInit byte = 1
	signalDialAck  byte = 2
	signalData     byte = 3
	signalClose    byte = 4
)

type dialInitMessage struct {
	Candidates []string `json:"candidates,omitempty"`
}

type dialAckMessage struct {
	Candidates []string `json:"candidates,omitempty"`
}

type signalMessage struct {
	Type      byte
	SessionID [16]byte
	Payload   []byte
}

func encodeSignalMessage(message signalMessage) []byte {
	out := make([]byte, 0, 17+len(message.Payload))
	out = append(out, message.Type)
	out = append(out, message.SessionID[:]...)
	out = append(out, message.Payload...)
	return out
}

func decodeSignalMessage(raw []byte) (signalMessage, error) {
	var message signalMessage
	if len(raw) < 17 {
		return message, fmt.Errorf("signal message too short")
	}
	message.Type = raw[0]
	copy(message.SessionID[:], raw[1:17])
	message.Payload = append([]byte(nil), raw[17:]...)
	return message, nil
}

func marshalDialInit(message dialInitMessage) ([]byte, error) {
	return json.Marshal(message)
}

func unmarshalDialInit(raw []byte) (dialInitMessage, error) {
	var message dialInitMessage
	err := json.Unmarshal(raw, &message)
	return message, err
}

func marshalDialAck(message dialAckMessage) ([]byte, error) {
	return json.Marshal(message)
}

func unmarshalDialAck(raw []byte) (dialAckMessage, error) {
	var message dialAckMessage
	err := json.Unmarshal(raw, &message)
	return message, err
}
