package interfaces

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	vpntypes "github.com/ApostolDmitry/vpner/internal/vpn"
)

const (
	interfaceStatusURL  = "http://127.0.0.1:79/rci/show/interface"
	interfaceControlURL = "http://127.0.0.1:79/rci/interface"
)

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
		if vpntypes.IsRouterManaged(iface.Type) {
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

func (c *routerClient) SetInterfaceState(ctx context.Context, interfaceName, desiredState string) error {
	requestBody := map[string]string{desiredState: "true"}
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("%s/%s", interfaceControlURL, interfaceName)
	resp, err := c.doRequest(ctx, http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (c *routerClient) GetInterfaceState(ctx context.Context, interfaceName string) (string, error) {
	url := fmt.Sprintf("%s/%s", interfaceControlURL, interfaceName)
	resp, err := c.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to fetch state: %w", err)
	}
	defer resp.Body.Close()

	var state InterfaceState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return "", fmt.Errorf("failed to decode state JSON: %w", err)
	}
	return state.State, nil
}

func (c *routerClient) GetISPState(ctx context.Context) (string, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, interfaceStatusURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to fetch interfaces: %w", err)
	}
	defer resp.Body.Close()

	var interfaces []Interface
	if err := json.NewDecoder(resp.Body).Decode(&interfaces); err != nil {
		return "", fmt.Errorf("failed to decode interfaces JSON: %w", err)
	}

	for _, iface := range interfaces {
		if iface.DefaultGW && iface.Global {
			return iface.State, nil
		}
	}
	return "down", nil
}
