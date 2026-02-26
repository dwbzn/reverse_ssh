package nat

import (
	"errors"
	"net"
	"sync"
	"time"
)

type connListener struct {
	addr net.Addr

	mu      sync.Mutex
	closed  bool
	closeCh chan struct{}
	connCh  chan net.Conn
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{
		addr:    addr,
		closeCh: make(chan struct{}),
		connCh:  make(chan net.Conn, 128),
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case <-l.closeCh:
		return nil, net.ErrClosed
	default:
	}

	select {
	case <-l.closeCh:
		return nil, net.ErrClosed
	case c := <-l.connCh:
		if c == nil {
			return nil, net.ErrClosed
		}
		return c, nil
	}
}

func (l *connListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	l.closed = true
	close(l.closeCh)
	return nil
}

func (l *connListener) Addr() net.Addr {
	return l.addr
}

func (l *connListener) push(c net.Conn) error {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return net.ErrClosed
	}

	select {
	case <-l.closeCh:
		return net.ErrClosed
	case l.connCh <- c:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("ts relay listener overloaded")
	}
}
