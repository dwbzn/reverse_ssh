package nat

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

type derpFrameType byte

const (
	derpMagic = "DERP🔑"

	derpFrameServerKey  derpFrameType = 0x01
	derpFrameClientInfo derpFrameType = 0x02
	derpFrameServerInfo derpFrameType = 0x03
	derpFrameSendPacket derpFrameType = 0x04
	derpFrameRecvPacket derpFrameType = 0x05
	derpFrameKeepAlive  derpFrameType = 0x06
	derpFramePing       derpFrameType = 0x12
	derpFramePong       derpFrameType = 0x13

	derpMaxFrameSize = 1 << 20
)

func writeDERPFrameHeader(w *bufio.Writer, typ derpFrameType, frameLen uint32) error {
	if err := w.WriteByte(byte(typ)); err != nil {
		return err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], frameLen)
	_, err := w.Write(length[:])
	return err
}

func writeDERPFrame(w *bufio.Writer, typ derpFrameType, payload []byte) error {
	if err := writeDERPFrameHeader(w, typ, uint32(len(payload))); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return w.Flush()
}

func readDERPFrameHeader(r *bufio.Reader) (derpFrameType, uint32, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return 0, 0, err
	}
	return derpFrameType(typ), binary.BigEndian.Uint32(length[:]), nil
}

func readDERPFramePayload(r *bufio.Reader, length uint32) ([]byte, error) {
	if length > derpMaxFrameSize {
		return nil, fmt.Errorf("derp frame too large: %d", length)
	}
	payload := make([]byte, int(length))
	if length == 0 {
		return payload, nil
	}
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
