package nat

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
	"golang.org/x/crypto/curve25519"
)

type fakeDERPServer struct {
	t      *testing.T
	server *httptest.Server

	private [32]byte
	public  [32]byte

	mu      sync.Mutex
	clients map[[32]byte]*fakeDERPClient
}

type fakeDERPClient struct {
	key [32]byte

	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	writeMu sync.Mutex
}

func newFakeDERPServer(t *testing.T) (*fakeDERPServer, vderp.Node) {
	t.Helper()

	f := &fakeDERPServer{
		t:       t,
		clients: make(map[[32]byte]*fakeDERPClient),
	}

	if _, err := rand.Read(f.private[:]); err != nil {
		t.Fatalf("failed to generate derp private key: %v", err)
	}
	clampCurve25519Private(f.private[:])
	curve25519.ScalarBaseMult(&f.public, &f.private)

	f.server = httptest.NewServer(http.HandlerFunc(f.handle))

	u, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatalf("failed to parse fake derp server url: %v", err)
	}
	host, portRaw, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("failed to split fake derp host: %v", err)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		t.Fatalf("failed to parse fake derp port: %v", err)
	}

	return f, vderp.Node{
		Name:             "fake-derp",
		RegionID:         1,
		HostName:         host,
		DERPPort:         port,
		InsecureForTests: true,
	}
}

func (f *fakeDERPServer) Close() {
	if f.server != nil {
		f.server.Close()
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, client := range f.clients {
		_ = client.conn.Close()
	}
	f.clients = map[[32]byte]*fakeDERPClient{}
}

func (f *fakeDERPServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/derp" {
		http.NotFound(w, r)
		return
	}

	if !strings.EqualFold(r.Header.Get("Upgrade"), "DERP") {
		http.Error(w, "upgrade required", http.StatusBadRequest)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}

	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}

	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n")
	_ = rw.Flush()

	if err := writeDERPFrame(rw.Writer, derpFrameServerKey, append([]byte(derpMagic), f.public[:]...)); err != nil {
		_ = conn.Close()
		return
	}

	typ, frameLen, err := readDERPFrameHeader(rw.Reader)
	if err != nil || typ != derpFrameClientInfo {
		_ = conn.Close()
		return
	}
	payload, err := readDERPFramePayload(rw.Reader, frameLen)
	if err != nil || len(payload) < 32 {
		_ = conn.Close()
		return
	}

	var clientKey [32]byte
	copy(clientKey[:], payload[:32])
	client := &fakeDERPClient{
		key:  clientKey,
		conn: conn,
		br:   rw.Reader,
		bw:   rw.Writer,
	}

	f.mu.Lock()
	f.clients[clientKey] = client
	f.mu.Unlock()

	go f.serveClient(client)
}

func (f *fakeDERPServer) serveClient(client *fakeDERPClient) {
	defer func() {
		_ = client.conn.Close()
		f.mu.Lock()
		delete(f.clients, client.key)
		f.mu.Unlock()
	}()

	for {
		typ, frameLen, err := readDERPFrameHeader(client.br)
		if err != nil {
			return
		}
		payload, err := readDERPFramePayload(client.br, frameLen)
		if err != nil {
			return
		}

		switch typ {
		case derpFrameSendPacket:
			if len(payload) < 32 {
				continue
			}
			var dst [32]byte
			copy(dst[:], payload[:32])
			data := payload[32:]
			f.forwardPacket(client.key, dst, data)
		case derpFramePing:
			if len(payload) < 8 {
				continue
			}
			pong := append([]byte(nil), payload[:8]...)
			_ = client.writeFrame(derpFramePong, pong)
		}
	}
}

func (f *fakeDERPServer) forwardPacket(src, dst [32]byte, payload []byte) {
	f.mu.Lock()
	target := f.clients[dst]
	f.mu.Unlock()
	if target == nil {
		return
	}

	framePayload := make([]byte, 0, 32+len(payload))
	framePayload = append(framePayload, src[:]...)
	framePayload = append(framePayload, payload...)
	_ = target.writeFrame(derpFrameRecvPacket, framePayload)
}

func (c *fakeDERPClient) writeFrame(typ derpFrameType, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeDERPFrame(c.bw, typ, payload)
}

func newMapServerForNode(node vderp.Node) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, fmt.Sprintf(`{"Regions":{"1":{"RegionID":1,"RegionCode":"test","RegionName":"test","Nodes":[{"Name":%q,"RegionID":1,"HostName":%q,"DERPPort":%d,"InsecureForTests":true}]}}}`,
			node.Name, node.HostName, node.DERPPort))
	}))
}
