package nat

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	derpReadBufferSize  = 64 * 1024
	derpWriteBufferSize = 128 * 1024
	derpFlushInterval   = 2 * time.Millisecond
	derpFlushThreshold  = 64 * 1024
	derpFlushNowSize    = 16 * 1024
)

type derpPacket struct {
	Source  [32]byte
	Payload []byte
}

type derpClient struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	serverPublic [32]byte
	privateKey   [32]byte
	publicKey    [32]byte

	writeMu sync.Mutex

	closed    chan struct{}
	closeOnce sync.Once
}

type derpClientInfo struct {
	Version     int  `json:"version,omitempty"`
	CanAckPings bool `json:"CanAckPings,omitempty"`
}

func newDERPClient(ctx context.Context, node vderp.Node, privateKey [32]byte) (*derpClient, error) {
	conn, err := dialDERPHTTP(ctx, node)
	if err != nil {
		return nil, err
	}

	br := bufio.NewReaderSize(conn, derpReadBufferSize)
	bw := bufio.NewWriterSize(conn, derpWriteBufferSize)

	client := &derpClient{
		conn:       conn,
		br:         br,
		bw:         bw,
		privateKey: privateKey,
		closed:     make(chan struct{}),
	}

	var public [32]byte
	curve25519.ScalarBaseMult(&public, &privateKey)
	client.publicKey = public

	if err := client.handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	go client.flushLoop()

	return client, nil
}

func dialDERPHTTP(ctx context.Context, node vderp.Node) (net.Conn, error) {
	if strings.TrimSpace(node.HostName) == "" {
		return nil, fmt.Errorf("derp node hostname is empty")
	}

	port := node.DERPPort
	if port == 0 {
		port = 443
	}
	address := net.JoinHostPort(node.HostName, fmt.Sprintf("%d", port))

	dialer := net.Dialer{Timeout: 8 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	httpConn := rawConn
	if !node.InsecureForTests {
		tlsConn := tls.Client(rawConn, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: node.HostName,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		httpConn = tlsConn
	}

	scheme := "https"
	if node.InsecureForTests {
		scheme = "http"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+address+"/derp", nil)
	if err != nil {
		_ = httpConn.Close()
		return nil, err
	}
	req.Header.Set("Upgrade", "DERP")
	req.Header.Set("Connection", "Upgrade")

	br := bufio.NewReaderSize(httpConn, derpReadBufferSize)
	bw := bufio.NewWriterSize(httpConn, derpWriteBufferSize)
	if err := req.Write(bw); err != nil {
		_ = httpConn.Close()
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		_ = httpConn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = httpConn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		_ = httpConn.Close()
		return nil, fmt.Errorf("derp upgrade failed: %s (%s)", resp.Status, strings.TrimSpace(string(body)))
	}
	resp.Body.Close()

	return &readWriteConn{
		Conn:   httpConn,
		reader: br,
	}, nil
}

func (c *derpClient) handshake() error {
	typ, frameLen, err := readDERPFrameHeader(c.br)
	if err != nil {
		return err
	}
	if typ != derpFrameServerKey {
		return fmt.Errorf("unexpected derp greeting frame %d", typ)
	}
	payload, err := readDERPFramePayload(c.br, frameLen)
	if err != nil {
		return err
	}
	if len(payload) < len(derpMagic)+32 {
		return fmt.Errorf("short derp server key frame")
	}
	if string(payload[:len(derpMagic)]) != derpMagic {
		return fmt.Errorf("invalid derp magic")
	}
	copy(c.serverPublic[:], payload[len(derpMagic):len(derpMagic)+32])

	infoBytes, err := json.Marshal(derpClientInfo{
		Version:     2,
		CanAckPings: true,
	})
	if err != nil {
		return err
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}

	encrypted := box.Seal(nonce[:], infoBytes, &nonce, &c.serverPublic, &c.privateKey)
	clientInfo := make([]byte, 0, 32+len(encrypted))
	clientInfo = append(clientInfo, c.publicKey[:]...)
	clientInfo = append(clientInfo, encrypted...)

	return writeDERPFrame(c.bw, derpFrameClientInfo, clientInfo)
}

func (c *derpClient) Send(dst [32]byte, payload []byte) error {
	if len(payload) > 64*1024 {
		return fmt.Errorf("derp payload too large: %d", len(payload))
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := writeDERPSendPacket(c.bw, dst, payload); err != nil {
		return err
	}
	if len(payload) >= derpFlushNowSize || c.bw.Buffered() >= derpFlushThreshold {
		return c.bw.Flush()
	}
	return nil
}

func (c *derpClient) sendPong(in [8]byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeDERPFrame(c.bw, derpFramePong, in[:])
}

func (c *derpClient) Recv() (derpPacket, error) {
	for {
		typ, frameLen, err := readDERPFrameHeader(c.br)
		if err != nil {
			return derpPacket{}, err
		}
		payload, err := readDERPFramePayload(c.br, frameLen)
		if err != nil {
			return derpPacket{}, err
		}

		switch typ {
		case derpFrameRecvPacket:
			if len(payload) < 32 {
				continue
			}
			var src [32]byte
			copy(src[:], payload[:32])
			data := payload[32:]
			return derpPacket{Source: src, Payload: data}, nil
		case derpFramePing:
			if len(payload) < 8 {
				continue
			}
			var ping [8]byte
			copy(ping[:], payload[:8])
			_ = c.sendPong(ping)
		case derpFrameKeepAlive, derpFrameServerInfo:
			continue
		default:
			continue
		}
	}
}

func (c *derpClient) Close() error {
	var retErr error
	c.closeOnce.Do(func() {
		close(c.closed)

		c.writeMu.Lock()
		if c.bw != nil && c.bw.Buffered() > 0 {
			_ = c.bw.Flush()
		}
		c.writeMu.Unlock()

		if c.conn == nil {
			return
		}
		retErr = c.conn.Close()
		c.conn = nil
	})
	return retErr
}

func (c *derpClient) flushLoop() {
	ticker := time.NewTicker(derpFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
		}

		c.writeMu.Lock()
		if c.bw.Buffered() > 0 {
			_ = c.bw.Flush()
		}
		c.writeMu.Unlock()
	}
}

func writeDERPSendPacket(w *bufio.Writer, dst [32]byte, payload []byte) error {
	frameLen := 32 + len(payload)
	if err := writeDERPFrameHeader(w, derpFrameSendPacket, uint32(frameLen)); err != nil {
		return err
	}
	if _, err := w.Write(dst[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

type readWriteConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *readWriteConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *readWriteConn) Write(p []byte) (int, error) {
	return c.Conn.Write(p)
}
