package dohclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ApostolDmitry/vpner/internal/common/dnsresolver"
	"github.com/miekg/dns"
)

type ResolverConfig struct {
	Servers            []string `yaml:"servers"`
	Resolvers          []string `yaml:"resolvers"`
	CacheTTL           int      `yaml:"cache-ttl"`
	Verbose            bool     `yaml:"verbose"`
	InsecureSkipVerify bool     `yaml:"insecure-skip-verify"`
}

type Resolver struct {
	config ResolverConfig

	httpClient *http.Client

	cache   map[string]cachedEntry
	cacheMu sync.RWMutex
}

type cachedEntry struct {
	IPs      []net.IP
	CachedAt time.Time
}

func NewResolver(cfg ResolverConfig) *Resolver {

	r := &Resolver{
		config: cfg,
		cache:  make(map[string]cachedEntry),
	}

	transport := &http.Transport{
		DialContext:           r.dialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     60 * time.Second,
	}

	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	r.httpClient = &http.Client{
		Timeout:   8 * time.Second,
		Transport: transport,
	}

	return r
}

func (r *Resolver) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// если уже IP — используем напрямую
	if net.ParseIP(host) != nil {

		dialer := &net.Dialer{Timeout: 5 * time.Second}

		return dialer.DialContext(ctx, network, addr)
	}

	ips, err := r.resolveHost(host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}

	var lastErr error

	for _, ip := range ips {

		target := net.JoinHostPort(ip.String(), port)

		conn, err := dialer.DialContext(ctx, network, target)

		if err == nil {
			return conn, nil
		}

		lastErr = err
	}

	return nil, fmt.Errorf("all bootstrap IPs failed for %s: %w", host, lastErr)
}

func (r *Resolver) ForwardQuery(query []byte) ([]byte, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	type result struct {
		resp []byte
		err  error
	}

	ch := make(chan result, len(r.config.Servers))

	for _, server := range r.config.Servers {

		server := server

		go func() {

			resp, err := r.forwardToServer(ctx, server, query)

			select {

			case ch <- result{resp, err}:

			case <-ctx.Done():
			}

		}()
	}

	var lastErr error

	for i := 0; i < len(r.config.Servers); i++ {

		select {

		case res := <-ch:

			if res.err == nil {
				return res.resp, nil
			}

			lastErr = res.err

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if lastErr == nil {
		lastErr = errors.New("all DoH servers failed")
	}

	return nil, lastErr
}

func (r *Resolver) forwardToServer(ctx context.Context, serverURL string, query []byte) ([]byte, error) {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		serverURL,
		bytes.NewBuffer(query),
	)

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {

		io.Copy(io.Discard, resp.Body)

		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (r *Resolver) resolveHost(host string) ([]net.IP, error) {

	r.cacheMu.RLock()

	entry, ok := r.cache[host]

	r.cacheMu.RUnlock()

	if ok && time.Since(entry.CachedAt) < time.Duration(r.config.CacheTTL)*time.Second {

		return entry.IPs, nil
	}

	var lastErr error

	for _, resolver := range r.config.Resolvers {

		ips, err := dnsresolver.Query(resolver, host)

		if err != nil {
			lastErr = err
			continue
		}

		if len(ips) == 0 {
			continue
		}

		r.cacheMu.Lock()

		r.cache[host] = cachedEntry{
			IPs:      ips,
			CachedAt: time.Now(),
		}

		r.cacheMu.Unlock()

		return ips, nil
	}

	if lastErr == nil {
		lastErr = errors.New("bootstrap resolvers failed")
	}

	return nil, lastErr
}

func (r *Resolver) ResolveDomain(domain string, qtype uint16) ([]net.IP, error) {

	msg := new(dns.Msg)

	msg.SetQuestion(dns.Fqdn(domain), qtype)

	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	respData, err := r.ForwardQuery(packed)
	if err != nil {
		return nil, err
	}

	resp := new(dns.Msg)

	if err := resp.Unpack(respData); err != nil {
		return nil, err
	}

	var ips []net.IP

	for _, ans := range resp.Answer {

		switch rr := ans.(type) {

		case *dns.A:
			ips = append(ips, rr.A)

		case *dns.AAAA:
			ips = append(ips, rr.AAAA)

		}
	}
	return ips, nil
}
