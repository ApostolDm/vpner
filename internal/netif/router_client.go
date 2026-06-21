package netif

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ApostolDmitry/vpner/internal/vpnkind"
)

const interfaceStatusURL = "http://127.0.0.1:79/rci/show/interface"

type routerClient struct {
	httpClient *http.Client
}

func newRouterClient(client *http.Client) *routerClient {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &routerClient{httpClient: client}
}

func (c *routerClient) doRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpClient.Do(req)
}

func (c *routerClient) FetchInterfaces(ctx context.Context) (map[string]Interface, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, interfaceStatusURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch interfaces: %w", err)
	}
	defer resp.Body.Close()

	var interfacesMap map[string]Interface
	if err := json.NewDecoder(resp.Body).Decode(&interfacesMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal interface JSON: %w", err)
	}

	interfacesFiltered := make(map[string]Interface)
	for id, iface := range interfacesMap {
		if vpnkind.IsRouterManaged(iface.Type) {
			interfacesFiltered[id] = iface
		}
	}
	return interfacesFiltered, nil
}

func (c *routerClient) LookupType(ctx context.Context, name string) (string, bool) {
	interfacesMap, err := c.FetchInterfaces(ctx)
	if err != nil {
		return "", false
	}
	iface, exists := interfacesMap[name]
	return iface.Type, exists
}
