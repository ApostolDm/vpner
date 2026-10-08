package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/miekg/dns"
)

const hedgeDelay = 300 * time.Millisecond

func (r *Upstream) ForwardQuery(query []byte) ([]byte, error) {
	if len(r.servers) == 0 {
		return nil, errors.New("no DoH servers configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), secs(r.config.HTTPTimeout))
	defer cancel()

	type result struct {
		server *upstreamState
		resp   []byte
		err    error
	}

	servers := r.orderServers()
	ch := make(chan result, len(servers))
	launch := func(s *upstreamState) {
		go func() {
			start := time.Now()
			resp, err := r.forwardToServer(ctx, s.server, query)
			r.updateServerStat(s, time.Since(start), err)
			ch <- result{server: s, resp: resp, err: err}
		}()
	}

	hedge := time.NewTimer(hedgeDelay)
	defer hedge.Stop()

	launched, finished := 0, 0
	launch(servers[launched])
	launched++

	var errs []string
	for finished < launched {
		select {
		case res := <-ch:
			finished++
			if res.err == nil {
				logx.Debugf("doh server %s answered", res.server.server)
				return res.resp, nil
			}
			errs = append(errs, fmt.Sprintf("%s: %v", res.server.server, res.err))
			if launched < len(servers) {
				launch(servers[launched])
				launched++
			}
		case <-hedge.C:
			if launched < len(servers) {
				launch(servers[launched])
				launched++
				hedge.Reset(hedgeDelay)
			}
		case <-ctx.Done():
			if len(errs) > 0 {
				return nil, fmt.Errorf("doh timeout: %s", strings.Join(errs, "; "))
			}
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("all DoH servers failed: %s", strings.Join(errs, "; "))
}

func (r *Upstream) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	var ips []net.IP
	var lastErr error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if err := ctx.Err(); err != nil {
			return ips, err
		}
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), qtype)
		msg.RecursionDesired = true
		packed, err := msg.Pack()
		if err != nil {
			lastErr = err
			continue
		}
		raw, err := r.ForwardQuery(packed)
		if err != nil {
			lastErr = err
			continue
		}
		var resp dns.Msg
		if err := resp.Unpack(raw); err != nil {
			lastErr = err
			continue
		}
		ips = append(ips, extractIPs(&resp)...)
	}
	if len(ips) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return ips, nil
}

func (s *upstreamState) healthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastError.IsZero() || s.lastSuccess.After(s.lastError)
}

func (r *Upstream) orderServers() []*upstreamState {
	out := append([]*upstreamState(nil), r.servers...)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })

	sort.SliceStable(out, func(i, j int) bool {
		if hi, hj := out[i].healthy(), out[j].healthy(); hi != hj {
			return hi
		}
		if si, sj := out[i].successes.Load(), out[j].successes.Load(); si != sj {
			return si > sj
		}
		if fi, fj := out[i].failures.Load(), out[j].failures.Load(); fi != fj {
			return fi < fj
		}
		li, lj := out[i].lastLatency.Load(), out[j].lastLatency.Load()
		if (li == 0) != (lj == 0) {
			return li == 0
		}
		return li < lj
	})
	return out
}

func (r *Upstream) updateServerStat(s *upstreamState, latency time.Duration, err error) {
	s.lastLatency.Store(latency.Nanoseconds())

	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.successes.Add(1)
		s.lastSuccess = time.Now()
		return
	}
	s.failures.Add(1)
	s.lastError = time.Now()
}

func (r *Upstream) forwardToServer(ctx context.Context, serverURL string, query []byte) ([]byte, error) {
	select {
	case r.reqSem <- struct{}{}:
		defer func() { <-r.reqSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH url %q: %w", serverURL, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "vpner-dohclient/1.0")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	if ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))); ct != "" &&
		!strings.Contains(ct, "application/dns-message") {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("unexpected content-type %q: %q", ct, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("empty DoH response")
	}

	var msg dns.Msg
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("invalid dns message in DoH response: %w", err)
	}
	return body, nil
}
