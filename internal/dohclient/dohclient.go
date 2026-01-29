package dohclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/common/dnsresolver"
	"github.com/miekg/dns"
)

type ResolverConfig struct {
	Servers   []string `yaml:"servers"`
	Resolvers []string `yaml:"resolvers"`
	CacheTTL  int      `yaml:"cache-ttl"`
	Verbose   bool     `yaml:"verbose"`
}

type Resolver struct {
	config     ResolverConfig
	httpClient *http.Client
	cache      map[string]cachedEntry
	cacheMu    sync.RWMutex
}

type cachedEntry struct {
	IPs      []net.IP
	CachedAt time.Time
}

func NewResolver(cfg ResolverConfig) *Resolver {
	return &Resolver{
		config:     cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      make(map[string]cachedEntry),
	}
}

func (r *Resolver) ForwardQuery(query []byte) ([]byte, error) {
	for _, server := range r.config.Servers {
		resp, err := r.forwardToServer(server, query)
		if err == nil {
			return resp, nil
		}
		if r.config.Verbose {
			log.Printf("DoH server failed: %s, err: %v", server, err)
		}
	}
	return nil, errors.New("all DoH servers failed")
}

func (r *Resolver) forwardToServer(serverURL string, query []byte) ([]byte, error) {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid DoH server URL: %s", serverURL)
	}
	port := parsed.Port()
	if port == "" {
		if strings.EqualFold(parsed.Scheme, "http") {
			port = "80"
		} else {
			port = "443"
		}
	}

	targetHost := parsed.Host
	ipHost := host
	if net.ParseIP(host) == nil {
		ips, err := r.GetDoHIPs(serverURL)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IPs resolved for DoH host %s", host)
		}
		ipHost = ips[0].String()
	}

	requestURL := *parsed
	requestURL.Host = net.JoinHostPort(ipHost, port)

	req, err := http.NewRequest("POST", requestURL.String(), bytes.NewBuffer(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Host = targetHost

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if strings.EqualFold(parsed.Scheme, "https") && net.ParseIP(host) == nil {
		transport.TLSClientConfig = &tls.Config{ServerName: host}
	}

	client := &http.Client{
		Timeout:   r.httpClient.Timeout,
		Transport: transport,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (r *Resolver) GetDoHIPs(dohServerURL string) ([]net.IP, error) {
	r.cacheMu.RLock()
	entry, found := r.cache[dohServerURL]
	r.cacheMu.RUnlock()

	if found && time.Since(entry.CachedAt) < time.Duration(r.config.CacheTTL)*time.Second {
		return entry.IPs, nil
	}

	host, err := extractHost(dohServerURL)
	if err != nil {
		return nil, err
	}
	for _, resolver := range r.config.Resolvers {
		ips, err := dnsresolver.Query(resolver, host)
		if err == nil && len(ips) > 0 {
			r.cacheMu.Lock()
			r.cache[dohServerURL] = cachedEntry{IPs: ips, CachedAt: time.Now()}
			r.cacheMu.Unlock()
			return ips, nil
		}
	}
	return nil, errors.New("failed to resolve DoH IPs")
}

func extractHost(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("invalid URL host: %s", rawURL)
	}
	return host, nil
}

func (r *Resolver) ResolveDomain(domain string, qtype uint16) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)

	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS query: %w", err)
	}

	respData, err := r.ForwardQuery(packed)
	if err != nil {
		return nil, fmt.Errorf("DoH query failed: %w", err)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respData); err != nil {
		return nil, fmt.Errorf("failed to unpack response: %w", err)
	}

	var result []net.IP
	for _, answer := range respMsg.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			result = append(result, rr.A)
		case *dns.AAAA:
			result = append(result, rr.AAAA)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no A/AAAA records found for domain %s", domain)
	}

	return result, nil
}
