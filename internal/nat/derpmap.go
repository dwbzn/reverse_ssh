package nat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

const (
	DefaultDERPMapURL = "https://login.tailscale.com/derpmap/default"
	DERPMapURLEnvVar  = "RSSH_DERP_MAP_URL"
)

var (
	cachedDERPMaps   = make(map[string]*vderp.Map)
	cachedDERPMapsMu sync.Mutex
)

func EffectiveDERPMapURL(explicitURL string) string {
	if strings.TrimSpace(explicitURL) != "" {
		return strings.TrimSpace(explicitURL)
	}
	if env := strings.TrimSpace(os.Getenv(DERPMapURLEnvVar)); env != "" {
		return env
	}
	return DefaultDERPMapURL
}

func FetchDERPMap(ctx context.Context, explicitURL string) (*vderp.Map, error) {
	url := EffectiveDERPMapURL(explicitURL)

	cachedDERPMapsMu.Lock()
	if m, ok := cachedDERPMaps[url]; ok {
		cachedDERPMapsMu.Unlock()
		return m, nil
	}
	cachedDERPMapsMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}

	parsedMap, err := vderp.ParseJSON(body)
	if err == nil {
		cachedDERPMapsMu.Lock()
		cachedDERPMaps[url] = parsedMap
		cachedDERPMapsMu.Unlock()
	}

	return parsedMap, err
}
