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

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	client := &derpClient{
		conn:       conn,
		br:         br,
		bw:         bw,
		privateKey: privateKey,
	}

	var public [32]byte
	curve25519.ScalarBaseMult(&public, &privateKey)
	client.publicKey = public

	if err := client.handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}

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

	br := bufio.NewReader(httpConn)
	bw := bufio.NewWriter(httpConn)
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
		writer: bw,
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
	framePayload := make([]byte, 0, 32+len(payload))
	framePayload = append(framePayload, dst[:]...)
	framePayload = append(framePayload, payload...)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeDERPFrame(c.bw, derpFrameSendPacket, framePayload)
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
			data := append([]byte(nil), payload[32:]...)
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
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

type readWriteConn struct {
	net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func (c *readWriteConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *readWriteConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if err != nil {
		return n, err
	}
	if err := c.writer.Flush(); err != nil {
		return n, err
	}
	return n, nil
}
