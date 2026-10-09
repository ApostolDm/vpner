package cli

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ApostolDmitry/vpner/internal/buildinfo"
)

const subMaxBody = 4 << 20

type linkSource struct {
	file     string
	index    int
	insecure bool
}

func (s linkSource) resolve(args []string) ([]string, error) {
	text, err := s.text(args)
	if err != nil {
		return nil, err
	}
	if isHTTPURL(text) {
		if text, err = fetchSubscription(text, s.insecure); err != nil {
			return nil, err
		}
	}
	links := splitLinks(text)
	if len(links) == 0 {
		return nil, fmt.Errorf("no links found (expected vless://, vmess://, trojan://, ss://, hysteria2:// lines or a base64 subscription)")
	}
	if s.index > 0 {
		if s.index > len(links) {
			return nil, fmt.Errorf("--index %d is out of range: the subscription has %d links", s.index, len(links))
		}
		return links[s.index-1 : s.index], nil
	}
	return links, nil
}

func (s linkSource) text(args []string) (string, error) {
	switch {
	case s.file != "" && len(args) > 0:
		return "", fmt.Errorf("pass either a link argument or --file, not both")
	case s.file == "" && len(args) == 0:
		return "", fmt.Errorf("a link, a subscription URL or --file is required")
	case s.file == "":
		return strings.TrimSpace(args[0]), nil
	}
	var data []byte
	var err error
	if s.file == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, subMaxBody))
	} else {
		data, err = os.ReadFile(s.file)
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func isHTTPURL(text string) bool {
	lower := strings.ToLower(text)
	return (strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")) && !strings.ContainsAny(text, "\n\r")
}

func fetchSubscription(rawURL string, insecure bool) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	if insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "vpnerctl/"+buildinfo.Version)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch subscription: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, subMaxBody))
	if err != nil {
		return "", fmt.Errorf("fetch subscription: %w", err)
	}
	return string(body), nil
}

func splitLinks(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if !strings.Contains(text, "://") {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding,
			base64.URLEncoding, base64.RawURLEncoding,
		} {
			if decoded, err := enc.DecodeString(strings.Join(strings.Fields(text), "")); err == nil && strings.Contains(string(decoded), "://") {
				text = string(decoded)
				break
			}
		}
	}
	var links []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "://") {
			continue
		}
		links = append(links, line)
	}
	return links
}

func describeLink(link string) string {
	desc := link
	if u, err := url.Parse(link); err == nil && u.Host != "" && u.Scheme != "vmess" {
		desc = u.Scheme + "://" + u.Host
		if u.Fragment != "" {
			desc += "  #" + u.Fragment
		}
	}
	if r := []rune(desc); len(r) > 48 {
		return string(r[:48]) + "…"
	}
	return desc
}
