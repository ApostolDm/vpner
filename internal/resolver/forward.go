package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/miekg/dns"
)

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
	for _, s := range servers {
		go func(s *upstreamState) {
			start := time.Now()
			resp, err := r.forwardToServer(ctx, s.server, query)
			r.updateServerStat(s, time.Since(start), err)
			select {
			case ch <- result{server: s, resp: resp, err: err}:
			case <-ctx.Done():
			}
		}(s)
	}

	var errs []string
	for range servers {
		select {
		case res := <-ch:
			if res.err == nil {
				logx.Debugf("doh server %s won race", res.server.server)
				return res.resp, nil
			}
			errs = append(errs, fmt.Sprintf("%s: %v", res.server.server, res.err))
		case <-ctx.Done():
			if len(errs) > 0 {
				return nil, fmt.Errorf("doh timeout: %s", strings.Join(errs, "; "))
			}
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("all DoH servers failed: %s", strings.Join(errs, "; "))
}

func (r *Upstream) orderServers() []*upstreamState {
	out := append([]*upstreamState(nil), r.servers...)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })

	sort.SliceStable(out, func(i, j int) bool {
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
