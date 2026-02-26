package nat

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

var (
	globalDERPPrivateKey [32]byte
	globalDERPKeyOnce    sync.Once
)

func getGlobalDERPIdentity() ([32]byte, error) {
	var err error
	globalDERPKeyOnce.Do(func() {
		globalDERPPrivateKey, _, err = randomDERPIdentity()
	})
	return globalDERPPrivateKey, err
}

func Dial(destination string, timeout time.Duration) (net.Conn, error) {
	token, err := ParseDestination(destination)
	if err != nil {
		return nil, err
	}

	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	derpMap, err := FetchDERPMap(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("ts derp map fetch failed: %w", err)
	}

	_, derpNode, err := pickNearestDERPNode(derpMap)
	if err != nil {
		return nil, fmt.Errorf("ts derp node selection failed: %w", err)
	}

	derpPrivate, err := getGlobalDERPIdentity()
	if err != nil {
		return nil, fmt.Errorf("ts derp key generation failed: %w", err)
	}
	signalCipher := newSignalCipher(derpPrivate, token.ServerDERPPublicKey)

	derpClient, err := newDERPClient(ctx, derpNode, derpPrivate)
	if err != nil {
		return nil, fmt.Errorf("ts derp connect failed: %w", err)
	}

	var sessionID [16]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		_ = derpClient.Close()
		return nil, err
	}

	var closeOnce sync.Once
	closeDERP := func() {
		closeOnce.Do(func() {
			_ = derpClient.Close()
		})
	}

	sendSignal := func(message signalMessage) error {
		raw := signalCipher.encode(message)
		return derpClient.Send(token.ServerDERPPublicKey, raw)
	}

	relay := newRelayConn(sessionID, "relay", token.ServerDERPPublicKey, sendSignal, closeDERP)
	ackCh := make(chan struct{}, 1)
	recvErrCh := make(chan error, 1)

	go func() {
		defer close(recvErrCh)
		for {
			packet, err := derpClient.Recv()
			if err != nil {
				relay.markRemoteClosed()
				recvErrCh <- err
				return
			}
			if packet.Source != token.ServerDERPPublicKey {
				continue
			}

			msg, err := signalCipher.decode(packet.Payload)
			if err != nil {
				continue
			}
			if msg.SessionID != sessionID {
				continue
			}

			switch msg.Type {
			case signalDialAck:
				select {
				case ackCh <- struct{}{}:
				default:
				}
			case signalData:
				relay.pushIncoming(msg.Payload)
			case signalClose:
				relay.markRemoteClosed()
			}
		}
	}()

	if err := sendSignal(signalMessage{
		Type:      signalDialInit,
		SessionID: sessionID,
	}); err != nil {
		closeDERP()
		return nil, err
	}

	select {
	case <-ackCh:
		log.Println("ts: relay session established")
		return relay, nil
	case err := <-recvErrCh:
		closeDERP()
		return nil, fmt.Errorf("ts derp session failed before ack: %w", err)
	case <-time.After(5 * time.Second):
		closeDERP()
		return nil, fmt.Errorf("ts derp session acknowledgement timeout")
	}
}
