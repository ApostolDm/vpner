package cli

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSplitLinksPlainAndBase64(t *testing.T) {
	t.Parallel()

	plain := "# comment\nvless://u@a.example.com:443?security=none#one\r\n\nss://YWVzOnB3@b.example.com:8388#two\ngarbage line\n"
	got := splitLinks(plain)
	if len(got) != 2 || !strings.HasPrefix(got[0], "vless://") || !strings.HasPrefix(got[1], "ss://") {
		t.Fatalf("plain: %v", got)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	if got := splitLinks(encoded); len(got) != 2 {
		t.Fatalf("base64: %v", got)
	}
	wrapped := base64.RawURLEncoding.EncodeToString([]byte(plain))
	wrapped = wrapped[:20] + "\n" + wrapped[20:]
	if got := splitLinks(wrapped); len(got) != 2 {
		t.Fatalf("wrapped raw-url base64: %v", got)
	}
	if got := splitLinks("   "); got != nil {
		t.Fatalf("empty input: %v", got)
	}
}

func TestLinkSourceResolveIndex(t *testing.T) {
	t.Parallel()

	body := "vless://u@a.example.com:443#one\ntrojan://p@b.example.com:443#two\n"
	all, err := linkSource{}.resolve([]string{body})
	if err != nil || len(all) != 2 {
		t.Fatalf("all: %v %v", all, err)
	}
	second, err := linkSource{index: 2}.resolve([]string{body})
	if err != nil || len(second) != 1 || !strings.HasPrefix(second[0], "trojan://") {
		t.Fatalf("index 2: %v %v", second, err)
	}
	if _, err := (linkSource{index: 3}).resolve([]string{body}); err == nil {
		t.Fatal("index out of range must fail")
	}
	if _, err := (linkSource{}).resolve(nil); err == nil {
		t.Fatal("missing input must fail")
	}
	if _, err := (linkSource{file: "x"}).resolve([]string{"vless://u@a:1"}); err == nil {
		t.Fatal("link and --file together must fail")
	}
}

func TestDescribeLink(t *testing.T) {
	t.Parallel()

	if got := describeLink("vless://uuid@a.example.com:443?security=reality#for%20inbound"); got != "vless://a.example.com:443  #for inbound" {
		t.Fatalf("got %q", got)
	}
	long := "vmess://" + strings.Repeat("a", 100)
	if got := describeLink(long); !strings.HasSuffix(got, "…") || len([]rune(got)) != 49 {
		t.Fatalf("got %q", got)
	}
	if !isHTTPURL("https://panel.example.com/sub/abc") || isHTTPURL("vless://x@y:1") || isHTTPURL("https://a\nvless://b") {
		t.Fatal("isHTTPURL misclassified")
	}
}
