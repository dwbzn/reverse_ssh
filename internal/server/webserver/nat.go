package webserver

import (
	"errors"
	"strings"
	"sync"
)

var (
	tsRelayMu        sync.Mutex
	tsRelayToken     string
	tsRelayBootstrap func() (string, error)
)

func SetTSBootstrap(bootstrap func() (string, error)) {
	tsRelayMu.Lock()
	defer tsRelayMu.Unlock()
	tsRelayBootstrap = bootstrap
}

func EnsureTSToken() (string, error) {
	tsRelayMu.Lock()
	defer tsRelayMu.Unlock()

	if tsRelayToken != "" {
		return tsRelayToken, nil
	}

	if tsRelayBootstrap == nil {
		return "", errors.New("ts relay bootstrap is not configured on this server")
	}

	token, err := tsRelayBootstrap()
	if err != nil {
		return "", err
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("ts relay bootstrap returned an empty token")
	}

	tsRelayToken = token
	return tsRelayToken, nil
}

func ResetTSRelay() {
	tsRelayMu.Lock()
	defer tsRelayMu.Unlock()

	tsRelayToken = ""
	tsRelayBootstrap = nil
}
