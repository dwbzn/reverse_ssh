package nat

import (
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
		ListenAddr: "127.0.0.1:42000",
	})
	if err == nil {
		t.Fatalf("Start() should fail when host private key is missing")
	}
}

func TestStartFailsWhenDERPMapUnavailable(t *testing.T) {
	t.Setenv(DERPMapURLEnvVar, "http://127.0.0.1:1/unreachable")

	_, err := Start(ServiceConfig{
		ListenAddr:     "127.0.0.1:42000",
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
