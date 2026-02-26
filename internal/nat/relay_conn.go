package nat

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const RelayAddrNetwork = "ts_relay"

type relayPeerAddr struct {
	source [32]byte
}

func (a relayPeerAddr) Network() string {
	return RelayAddrNetwork
}

func (a relayPeerAddr) String() string {
	return fmt.Sprintf("%s:%x", RelayAddrNetwork, a.source[:8])
}

type relayConn struct {
	sessionID [16]byte
	path      string
	remote    net.Addr

	sendSignal func(signalMessage) error
	onClosed   func()

	incoming chan []byte
	closed   chan struct{}

	mu            sync.Mutex
	readBuf       bytes.Buffer
	readDeadline  time.Time
	writeDeadline time.Time
	remoteClosed  bool

	closeOnce sync.Once
}

func newRelayConn(sessionID [16]byte, path string, source [32]byte, sendSignal func(signalMessage) error, onClosed func()) *relayConn {
	return &relayConn{
		sessionID:    sessionID,
		path:         path,
		remote:       relayPeerAddr{source: source},
		sendSignal:   sendSignal,
		onClosed:     onClosed,
		incoming:     make(chan []byte, 256),
		closed:       make(chan struct{}),
		remoteClosed: false,
	}
}

func (c *relayConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.readBuf.Len() > 0 {
			n, _ := c.readBuf.Read(b)
			c.mu.Unlock()
			return n, nil
		}
		remoteClosed := c.remoteClosed
		deadline := c.readDeadline
		c.mu.Unlock()

		if remoteClosed {
			return 0, io.EOF
		}

		var (
			timer   *time.Timer
			timerCh <-chan time.Time
		)
		if !deadline.IsZero() {
			until := time.Until(deadline)
			if until <= 0 {
				return 0, timeoutErr("read timeout")
			}
			timer = time.NewTimer(until)
			timerCh = timer.C
		}

		select {
		case payload, ok := <-c.incoming:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				c.mu.Lock()
				c.remoteClosed = true
				c.mu.Unlock()
				continue
			}
			c.mu.Lock()
			c.readBuf.Write(payload)
			c.mu.Unlock()
		case <-c.closed:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case <-timerCh:
			return 0, timeoutErr("read timeout")
		}
	}
}

func (c *relayConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	c.mu.Lock()
	remoteClosed := c.remoteClosed
	deadline := c.writeDeadline
	c.mu.Unlock()
	if remoteClosed {
		return 0, io.EOF
	}
	if deadlineExceeded(deadline) {
		return 0, timeoutErr("write timeout")
	}

	written := 0
	for written < len(b) {
		limit := len(b) - written
		if limit > 65000 {
			limit = 65000
		}
		chunk := append([]byte(nil), b[written:written+limit]...)
		if err := c.sendSignal(signalMessage{
			Type:      signalData,
			SessionID: c.sessionID,
			Payload:   chunk,
		}); err != nil {
			return written, err
		}
		written += limit
		if deadlineExceeded(deadline) {
			return written, timeoutErr("write timeout")
		}
	}

	return written, nil
}

func (c *relayConn) Close() error {
	var retErr error
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.onClosed != nil {
			c.onClosed()
		}
		if err := c.sendSignal(signalMessage{
			Type:      signalClose,
			SessionID: c.sessionID,
		}); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	})
	return retErr
}

func (c *relayConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *relayConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *relayConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *relayConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *relayConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

func (c *relayConn) Path() string {
	return c.path
}

func (c *relayConn) pushIncoming(payload []byte) bool {
	select {
	case <-c.closed:
		return false
	default:
	}

	select {
	case c.incoming <- append([]byte(nil), payload...):
		return true
	case <-c.closed:
		return false
	}
}

func (c *relayConn) markRemoteClosed() {
	c.mu.Lock()
	already := c.remoteClosed
	c.remoteClosed = true
	c.mu.Unlock()
	if already {
		return
	}
	close(c.incoming)
}

func deadlineExceeded(t time.Time) bool {
	return !t.IsZero() && time.Now().After(t)
}

type timeoutErr string

func (e timeoutErr) Error() string   { return string(e) }
func (e timeoutErr) Timeout() bool   { return true }
func (e timeoutErr) Temporary() bool { return true }
