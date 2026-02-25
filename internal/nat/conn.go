package nat

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/quic"
)

type pathConn struct {
	net.Conn
	path string
}

func (p *pathConn) Path() string {
	return p.path
}

func withPath(conn net.Conn, path string) net.Conn {
	return &pathConn{
		Conn: conn,
		path: path,
	}
}

type quicNetConn struct {
	mu sync.Mutex

	endpoint *quic.Endpoint
	conn     *quic.Conn
	stream   *quic.Stream

	readDeadline  time.Time
	writeDeadline time.Time
}

func newQUICNetConn(endpoint *quic.Endpoint, conn *quic.Conn, stream *quic.Stream) net.Conn {
	return &quicNetConn{
		endpoint: endpoint,
		conn:     conn,
		stream:   stream,
	}
}

func (q *quicNetConn) Read(b []byte) (int, error) {
	ctx, cancel := q.contextForRead()
	if cancel != nil {
		defer cancel()
	}
	q.stream.SetReadContext(ctx)
	return q.stream.Read(b)
}

func (q *quicNetConn) Write(b []byte) (int, error) {
	ctx, cancel := q.contextForWrite()
	if cancel != nil {
		defer cancel()
	}
	q.stream.SetWriteContext(ctx)

	n, err := q.stream.Write(b)
	if err != nil {
		return n, err
	}
	if err := q.stream.Flush(); err != nil {
		return n, err
	}
	return n, nil
}

func (q *quicNetConn) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	var errs []error
	if q.stream != nil {
		if err := q.stream.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if q.conn != nil {
		q.conn.Abort(nil)
	}
	if q.endpoint != nil {
		if err := q.endpoint.Close(context.Background()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (q *quicNetConn) LocalAddr() net.Addr {
	return addrPortToUDP(q.conn.LocalAddr())
}

func (q *quicNetConn) RemoteAddr() net.Addr {
	return addrPortToUDP(q.conn.RemoteAddr())
}

func (q *quicNetConn) SetDeadline(t time.Time) error {
	if err := q.SetReadDeadline(t); err != nil {
		return err
	}
	return q.SetWriteDeadline(t)
}

func (q *quicNetConn) SetReadDeadline(t time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.readDeadline = t
	return nil
}

func (q *quicNetConn) SetWriteDeadline(t time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.writeDeadline = t
	return nil
}

func deadlineContext(t time.Time) (context.Context, context.CancelFunc) {
	if t.IsZero() {
		return context.Background(), nil
	}
	return context.WithDeadline(context.Background(), t)
}

func (q *quicNetConn) contextForRead() (context.Context, context.CancelFunc) {
	q.mu.Lock()
	deadline := q.readDeadline
	q.mu.Unlock()
	return deadlineContext(deadline)
}

func (q *quicNetConn) contextForWrite() (context.Context, context.CancelFunc) {
	q.mu.Lock()
	deadline := q.writeDeadline
	q.mu.Unlock()
	return deadlineContext(deadline)
}

func addrPortToUDP(addr netip.AddrPort) net.Addr {
	ip := addr.Addr().AsSlice()
	parsed := net.IP(ip)
	return &net.UDPAddr{
		IP:   parsed,
		Port: int(addr.Port()),
	}
}
