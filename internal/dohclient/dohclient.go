package dohclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/utils"
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
	req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := r.httpClient.Do(req)
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

	if found && time.Since(entry.CachedAt) < time.Duration(r.config.CacheTTL) * time.Second  {
		return entry.IPs, nil
	}

	host := extractHost(dohServerURL)
	for _, resolver := range r.config.Resolvers {
		ips, err := utils.QueryDNSResolver(resolver, host)
		if err == nil && len(ips) > 0 {
			r.cacheMu.Lock()
			r.cache[dohServerURL] = cachedEntry{IPs: ips, CachedAt: time.Now()}
			r.cacheMu.Unlock()
			return ips, nil
		}
	}
	return nil, errors.New("failed to resolve DoH IPs")
}

func extractHost(url string) string {
	return strings.Split(url, "/")[2]
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
