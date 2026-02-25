package nat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	vderp "github.com/NHAS/reverse_ssh/internal/nat/derpmap"
)

const (
	DefaultDERPMapURL = "https://login.tailscale.com/derpmap/default"
	DERPMapURLEnvVar  = "RSSH_DERP_MAP_URL"
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

	return vderp.ParseJSON(body)
}
