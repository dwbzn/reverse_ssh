package webserver

import "sync"

var (
	natTokenMu sync.RWMutex
	natToken   string
)

func SetNATToken(token string) {
	natTokenMu.Lock()
	defer natTokenMu.Unlock()
	natToken = token
}

func NATToken() string {
	natTokenMu.RLock()
	defer natTokenMu.RUnlock()
	return natToken
}
