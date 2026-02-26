package nat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

const (
	maxPendingRelaySessions = 256
	pendingRelaySessionTTL  = 30 * time.Second
	relaySessionSweepPeriod = 10 * time.Second
)

type ServiceConfig struct {
	ListenAddr string

	HostPrivateKey []byte

	DERPMapURL string

	// Optional region hint to include in token.
	PreferredRegion uint16
}

type relaySessionKey struct {
	Peer      [32]byte
	SessionID [16]byte
}

type relaySession struct {
	conn         *relayConn
	accepted     bool
	lastActivity time.Time
}

type Service struct {
	token string

	listener *connListener

	derpNode    vderp.Node
	derpPrivate [32]byte

	derpMu     sync.RWMutex
	derpClient *derpClient

	sessionMu sync.Mutex
	sessions  map[relaySessionKey]*relaySession

	closed    chan struct{}
	closeOnce sync.Once
}

func Start(config ServiceConfig) (*Service, error) {
	if len(config.HostPrivateKey) == 0 {
		return nil, fmt.Errorf("host private key bytes cannot be empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	derpMap, err := FetchDERPMap(ctx, config.DERPMapURL)
	if err != nil {
		log.Printf("ts: derp map fetch failed: %v", err)
		return nil, fmt.Errorf("ts derp map fetch failed: %w", err)
	}

	derpPrivate, derpPublic, err := DeriveDERPIdentity(config.HostPrivateKey)
	if err != nil {
		return nil, err
	}

	listenHost, listenPort, err := splitHostPort(config.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid ts listen address: %w", err)
	}

	regionID, derpNode, err := pickDERPNode(derpMap, int(config.PreferredRegion))
	if err != nil {
		return nil, err
	}

	token := Token{
		Version:             TokenVersionV1,
		ServerDERPPublicKey: derpPublic,
		PreferredRegion:     uint16(regionID),
	}
	encodedToken, err := token.Encode()
	if err != nil {
		return nil, err
	}

	listenerIP := net.ParseIP(listenHost)
	if listenerIP == nil {
		listenerIP = net.IPv4zero
	}
	service := &Service{
		token:       encodedToken,
		listener:    newConnListener(&net.TCPAddr{IP: listenerIP, Port: listenPort}),
		derpNode:    derpNode,
		derpPrivate: derpPrivate,
		sessions:    make(map[relaySessionKey]*relaySession),
		closed:      make(chan struct{}),
	}

	if err := service.connectDERP(); err != nil {
		service.Close()
		return nil, err
	}

	go service.recvDERPLoop()
	go service.cleanupPendingRelaySessionsLoop()

	return service, nil
}

func (s *Service) connectDERP() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := newDERPClient(ctx, s.derpNode, s.derpPrivate)
	if err != nil {
		return err
	}

	s.derpMu.Lock()
	old := s.derpClient
	s.derpClient = client
	s.derpMu.Unlock()

	if old != nil {
		_ = old.Close()
	}

	return nil
}

func (s *Service) Listener() net.Listener {
	return s.listener
}

func (s *Service) Token() string {
	return s.token
}

func (s *Service) Close() error {
	var retErr error
	s.closeOnce.Do(func() {
		close(s.closed)

		if s.listener != nil {
			if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				retErr = err
			}
		}

		s.derpMu.Lock()
		dc := s.derpClient
		s.derpClient = nil
		s.derpMu.Unlock()
		if dc != nil {
			if err := dc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				retErr = errors.Join(retErr, err)
			}
		}

		s.sessionMu.Lock()
		all := make([]*relayConn, 0, len(s.sessions))
		for _, session := range s.sessions {
			all = append(all, session.conn)
		}
		s.sessions = make(map[relaySessionKey]*relaySession)
		s.sessionMu.Unlock()

		for _, conn := range all {
			conn.markRemoteClosed()
			_ = conn.Close()
		}
	})
	return retErr
}

func (s *Service) recvDERPLoop() {
	for {
		select {
		case <-s.closed:
			return
		default:
		}

		s.derpMu.RLock()
		client := s.derpClient
		s.derpMu.RUnlock()
		if client == nil {
			if !s.retryDERPConnect() {
				return
			}
			continue
		}

		packet, err := client.Recv()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			log.Printf("ts: derp receive failed: %v", err)

			s.derpMu.Lock()
			if s.derpClient == client {
				s.derpClient = nil
			}
			s.derpMu.Unlock()
			_ = client.Close()
			continue
		}

		message, err := decodeSignalMessage(packet.Payload, s.derpPrivate, packet.Source)
		if err != nil {
			continue
		}

		switch message.Type {
		case signalDialInit:
			s.handleDialInit(packet.Source, message)
		case signalData:
			s.routeRelayData(packet.Source, message.SessionID, message.Payload)
		case signalClose:
			s.routeRelayClose(packet.Source, message.SessionID)
		}
	}
}

func (s *Service) retryDERPConnect() bool {
	for {
		select {
		case <-s.closed:
			return false
		default:
		}

		if err := s.connectDERP(); err != nil {
			log.Printf("ts: derp reconnect failed: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		return true
	}
}

func (s *Service) handleDialInit(source [32]byte, message signalMessage) {
	sessionKey := relaySessionKey{
		Peer:      source,
		SessionID: message.SessionID,
	}

	sendSignal := func(msg signalMessage) error {
		return s.sendDERPSignal(source, msg)
	}

	s.sessionMu.Lock()
	session := s.sessions[sessionKey]
	if session == nil {
		if s.pendingRelaySessionsLocked() >= maxPendingRelaySessions {
			s.sessionMu.Unlock()
			log.Printf("ts: dropping session=%x, pending relay session limit reached", message.SessionID[:4])
			_ = s.sendDERPSignal(source, signalMessage{
				Type:      signalClose,
				SessionID: message.SessionID,
			})
			return
		}

		relay := newRelayConn(message.SessionID, "relay", source, sendSignal, func() {
			s.sessionMu.Lock()
			delete(s.sessions, sessionKey)
			s.sessionMu.Unlock()
		})
		s.sessions[sessionKey] = &relaySession{
			conn:         relay,
			lastActivity: time.Now(),
		}
	} else {
		session.lastActivity = time.Now()
	}
	s.sessionMu.Unlock()

	_ = s.sendDERPSignal(source, signalMessage{
		Type:      signalDialAck,
		SessionID: message.SessionID,
	})
}

func (s *Service) routeRelayData(source [32]byte, sessionID [16]byte, payload []byte) {
	key := relaySessionKey{Peer: source, SessionID: sessionID}

	var (
		conn      *relayConn
		needsPush bool
	)
	s.sessionMu.Lock()
	session := s.sessions[key]
	if session != nil {
		conn = session.conn
		session.lastActivity = time.Now()
		if !session.accepted {
			session.accepted = true
			needsPush = true
		}
	}
	s.sessionMu.Unlock()
	if conn == nil {
		return
	}

	if needsPush {
		if err := s.listener.push(conn); err != nil {
			conn.markRemoteClosed()
			_ = conn.Close()
			return
		}
	}
	conn.pushIncoming(payload)
}

func (s *Service) routeRelayClose(source [32]byte, sessionID [16]byte) {
	key := relaySessionKey{Peer: source, SessionID: sessionID}
	s.sessionMu.Lock()
	session := s.sessions[key]
	if session != nil {
		delete(s.sessions, key)
	}
	s.sessionMu.Unlock()
	var conn *relayConn
	accepted := false
	if session != nil {
		conn = session.conn
		accepted = session.accepted
	}
	if conn == nil {
		return
	}
	conn.markRemoteClosed()
	if !accepted {
		_ = conn.Close()
	}
}

func (s *Service) pendingRelaySessionsLocked() int {
	pending := 0
	for _, session := range s.sessions {
		if !session.accepted {
			pending++
		}
	}
	return pending
}

func (s *Service) cleanupPendingRelaySessionsLoop() {
	ticker := time.NewTicker(relaySessionSweepPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			s.prunePendingRelaySessions()
		}
	}
}

func (s *Service) prunePendingRelaySessions() {
	cutoff := time.Now().Add(-pendingRelaySessionTTL)

	var stale []*relayConn
	s.sessionMu.Lock()
	for key, session := range s.sessions {
		if session.accepted || session.lastActivity.After(cutoff) {
			continue
		}
		delete(s.sessions, key)
		stale = append(stale, session.conn)
	}
	s.sessionMu.Unlock()

	for _, conn := range stale {
		conn.markRemoteClosed()
		_ = conn.Close()
	}
}

func (s *Service) sendDERPSignal(destination [32]byte, message signalMessage) error {
	raw := encodeSignalMessage(message, s.derpPrivate, destination)

	s.derpMu.RLock()
	client := s.derpClient
	s.derpMu.RUnlock()
	if client == nil {
		return fmt.Errorf("derp client unavailable")
	}

	return client.Send(destination, raw)
}

func splitHostPort(addr string) (string, int, error) {
	host, portRaw, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return "", 0, err
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %d", port)
	}
	return host, port, nil
}
