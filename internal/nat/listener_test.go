package nat

import (
	"errors"
	"net"
	"testing"
)

func TestConnListenerAcceptReturnsClosedAfterClose(t *testing.T) {
	listener := newConnListener(&net.TCPAddr{IP: net.IPv4zero, Port: 0})

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, err := listener.Accept()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() error = %v, want %v", err, net.ErrClosed)
	}
}

func TestConnListenerAcceptPrefersClosedSignal(t *testing.T) {
	listener := newConnListener(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	if err := listener.push(serverSide); err != nil {
		t.Fatalf("push() error = %v", err)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, err := listener.Accept()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() error = %v, want %v", err, net.ErrClosed)
	}
}
