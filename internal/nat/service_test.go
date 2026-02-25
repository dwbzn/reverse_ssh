package nat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestStartFailsWithoutHostPrivateKey(t *testing.T) {
	_, err := Start(ServiceConfig{
		ListenAddr:   "127.0.0.1:42000",
		ExternalAddr: "127.0.0.1:42000",
	})
	if err == nil {
		t.Fatalf("Start() should fail when host private key is missing")
	}
}

func TestStartFailsWhenRelayDisabled(t *testing.T) {
	_, err := Start(ServiceConfig{
		ListenAddr:     "127.0.0.1:42000",
		ExternalAddr:   "127.0.0.1:42000",
		HostPrivateKey: []byte("test-key"),
		DisableRelay:   true,
	})
	if err == nil {
		t.Fatalf("Start() should fail when relay transport is disabled")
	}
}

func TestStartFailsWhenDERPMapUnavailable(t *testing.T) {
	t.Setenv(DERPMapURLEnvVar, "http://127.0.0.1:1/unreachable")

	_, err := Start(ServiceConfig{
		ListenAddr:     "127.0.0.1:42000",
		ExternalAddr:   "127.0.0.1:42000",
		HostPrivateKey: []byte("test-key"),
	})
	if err == nil {
		t.Fatalf("Start() should fail when DERP map fetch fails")
	}
}

func TestDialRelayPath(t *testing.T) {
	derpServer, node := newFakeDERPServer(t)
	defer derpServer.Close()

	mapServer := newMapServerForNode(node)
	defer mapServer.Close()
	t.Setenv(DERPMapURLEnvVar, mapServer.URL)

	listenAddr := mustPickTestAddr(t)
	service, err := Start(ServiceConfig{
		ListenAddr:     listenAddr,
		ExternalAddr:   listenAddr,
		HostPrivateKey: []byte("test-key-relay"),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer service.Close()

	go echoAcceptedConn(t, service.Listener())

	conn, err := Dial(DestinationPrefix+service.Token(), 5*time.Second)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()

	pathConn, ok := conn.(interface{ Path() string })
	if !ok {
		t.Fatalf("Dial() connection does not expose path")
	}
	if got := pathConn.Path(); got != "relay" {
		t.Fatalf("path = %q, want %q", got, "relay")
	}

	payload := []byte("hello-relay")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), string(payload))
	}
}

func TestDialOldDestinationAfterRestart(t *testing.T) {
	derpServer, node := newFakeDERPServer(t)
	defer derpServer.Close()

	mapServer := newMapServerForNode(node)
	defer mapServer.Close()
	t.Setenv(DERPMapURLEnvVar, mapServer.URL)

	listenAddr := mustPickTestAddr(t)
	hostKey := []byte("test-key-restart")

	serviceOne, err := Start(ServiceConfig{
		ListenAddr:     listenAddr,
		ExternalAddr:   listenAddr,
		HostPrivateKey: hostKey,
	})
	if err != nil {
		t.Fatalf("Start() first instance error = %v", err)
	}
	oldDestination := DestinationPrefix + serviceOne.Token()
	if err := serviceOne.Close(); err != nil {
		t.Fatalf("Close() first instance error = %v", err)
	}

	serviceTwo, err := Start(ServiceConfig{
		ListenAddr:     listenAddr,
		ExternalAddr:   listenAddr,
		HostPrivateKey: hostKey,
	})
	if err != nil {
		t.Fatalf("Start() second instance error = %v", err)
	}
	defer serviceTwo.Close()

	go echoAcceptedConn(t, serviceTwo.Listener())

	conn, err := Dial(oldDestination, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial() using old destination after restart error = %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-restart")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), string(payload))
	}
}

func mustPickTestAddr(t *testing.T) string {
	t.Helper()
	for i := 0; i < 40; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to allocate temp port: %v", err)
		}
		addr := l.Addr().String()
		_ = l.Close()

		host, portRaw, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		port, err := net.LookupPort("tcp", portRaw)
		if err != nil || port <= 0 || port >= 65535 {
			continue
		}
		return net.JoinHostPort(host, fmt.Sprintf("%d", port))
	}
	t.Fatalf("unable to allocate usable test port pair")
	return ""
}

func echoAcceptedConn(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "closed") || errorsIsNetClosed(err) {
			return
		}
		t.Errorf("Accept() error = %v", err)
		return
	}
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}

func errorsIsNetClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "use of closed network connection")
}

func TestHandleDialInitCapsPendingRelaySessions(t *testing.T) {
	service := &Service{
		sessions: make(map[relaySessionKey]*relaySession),
		closed:   make(chan struct{}),
	}

	payload, err := marshalDialInit(dialInitMessage{})
	if err != nil {
		t.Fatalf("marshalDialInit() error = %v", err)
	}

	source := [32]byte{1}
	for i := 0; i < maxPendingRelaySessions+32; i++ {
		var sessionID [16]byte
		binary.BigEndian.PutUint32(sessionID[12:], uint32(i))

		service.handleDialInit(source, signalMessage{
			Type:      signalDialInit,
			SessionID: sessionID,
			Payload:   payload,
		})
	}

	if got := len(service.sessions); got != maxPendingRelaySessions {
		t.Fatalf("pending session count = %d, want %d", got, maxPendingRelaySessions)
	}
}

func TestPrunePendingRelaySessionsRemovesStaleEntries(t *testing.T) {
	source := [32]byte{2}

	var staleSessionID [16]byte
	var freshSessionID [16]byte
	staleSessionID[0] = 1
	freshSessionID[0] = 2

	noOpSignal := func(signalMessage) error { return nil }
	service := &Service{
		sessions: make(map[relaySessionKey]*relaySession),
		closed:   make(chan struct{}),
	}

	staleConn := newRelayConn(staleSessionID, "relay", source, noOpSignal, nil)
	freshConn := newRelayConn(freshSessionID, "relay", source, noOpSignal, nil)

	service.sessions[relaySessionKey{Peer: source, SessionID: staleSessionID}] = &relaySession{
		conn:         staleConn,
		accepted:     false,
		lastActivity: time.Now().Add(-pendingRelaySessionTTL - time.Second),
	}
	service.sessions[relaySessionKey{Peer: source, SessionID: freshSessionID}] = &relaySession{
		conn:         freshConn,
		accepted:     false,
		lastActivity: time.Now(),
	}

	service.prunePendingRelaySessions()

	if _, ok := service.sessions[relaySessionKey{Peer: source, SessionID: staleSessionID}]; ok {
		t.Fatalf("stale session was not pruned")
	}
	if _, ok := service.sessions[relaySessionKey{Peer: source, SessionID: freshSessionID}]; !ok {
		t.Fatalf("fresh session should remain present")
	}
}

func TestRouteRelayCloseRemovesSession(t *testing.T) {
	source := [32]byte{3}
	sessionID := [16]byte{9}

	noOpSignal := func(signalMessage) error { return nil }
	conn := newRelayConn(sessionID, "relay", source, noOpSignal, nil)
	service := &Service{
		sessions: map[relaySessionKey]*relaySession{
			{Peer: source, SessionID: sessionID}: {
				conn:         conn,
				accepted:     false,
				lastActivity: time.Now(),
			},
		},
		closed: make(chan struct{}),
	}

	service.routeRelayClose(source, sessionID)

	if len(service.sessions) != 0 {
		t.Fatalf("expected session map to be empty after relay close, got %d entries", len(service.sessions))
	}
}
