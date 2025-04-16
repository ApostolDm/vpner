package dnsserver

import (
	"log"
	"strconv"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/common/logging"
	"github.com/ApostolDmitry/vpner/internal/common/patterns"
	"github.com/ApostolDmitry/vpner/internal/dohclient"
	"github.com/ApostolDmitry/vpner/internal/network"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

type ServerConfig struct {
	Port              int                 `yaml:"port"`
	MaxConcurrentConn int                 `yaml:"max-concurrent-connections"`
	Verbose           bool                `yaml:"verbose"`
	CustomResolve     map[string][]string `yaml:"custom-resolve"`
	Running           bool                `yaml:"running"`
}

type compiledResolverRule struct {
	Resolver string
	Pattern  string
}

type DNSServer struct {
	config         ServerConfig
	connSemaphore  chan struct{}
	unblockManager *network.UnblockManager
	customRules    []compiledResolverRule
	resolver       *dohclient.Resolver
	dnsServer      *dns.Server
	notifyStarted  func()
}

func NewDNSServer(cfg ServerConfig, um *network.UnblockManager, resolver *dohclient.Resolver) *DNSServer {
	s := &DNSServer{
		config:         cfg,
		connSemaphore:  make(chan struct{}, cfg.MaxConcurrentConn),
		unblockManager: um,
		resolver:       resolver,
	}

	for resolverAddr, entries := range cfg.CustomResolve {
		for _, raw := range entries {
			if err := patterns.Validate(raw); err != nil {
				logging.Errorf("ошибка в шаблоне customResolve %q: %v", raw, err)
				continue
			}
			s.customRules = append(s.customRules, compiledResolverRule{
				Resolver: resolverAddr,
				Pattern:  raw,
			})
		}
	}

	return s
}

func (s *DNSServer) Run(ctx context.Context) error {
	dns.HandleFunc(".", s.handleDNSRequest)

	addr := ":" + strconv.Itoa(s.config.Port)
	s.dnsServer = &dns.Server{Addr: addr, Net: "udp"}
	if s.notifyStarted != nil {
		s.dnsServer.NotifyStartedFunc = s.notifyStarted
	}

	go func() {
		<-ctx.Done()
		if s.config.Verbose {
			log.Println("DNS server shutdown initiated")
		}
		_ = s.dnsServer.Shutdown()
	}()

	if s.config.Verbose {
		log.Printf("Starting DNS server on port %d...", s.config.Port)
	}

	return s.dnsServer.ListenAndServe()
}

func (s *DNSServer) SetNotifyStartedFunc(fn func()) {
	s.notifyStarted = fn
}

func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if s.config.Verbose {
		log.Println("Received new DNS request")
	}

	s.connSemaphore <- struct{}{}
	defer func() { <-s.connSemaphore }()

	domain := extractDomain(r)
	if domain != "" {
		go s.processDomain(domain)
	}

	if resolverIP := s.matchCustomResolver(domain); resolverIP != "" {
		if s.config.Verbose {
			log.Printf("Domain %s resolved from custom %s", domain, resolverIP)
		}

		client := &dns.Client{Net: "udp"}
		resp, _, err := client.Exchange(r.Copy(), resolverIP)
		if err != nil {
			log.Printf("Custom resolver error: %v", err)
			return
		}
		resp.Id = r.Id
		_ = w.WriteMsg(resp)
		return
	}

	packed, err := r.Pack()
	if err != nil {
		log.Printf("Pack error: %v", err)
		return
	}

	resp, err := s.resolver.ForwardQuery(packed)
	if err != nil {
		log.Printf("DoH forward error: %v", err)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		log.Printf("Unpack error: %v", err)
		return
	}

	_ = w.WriteMsg(msg)
}

func (s *DNSServer) processDomain(domain string) {
	manager := network.NewIpRuleManager(s.unblockManager, s.resolver)
	if err := manager.CheckIPsInIpset(domain); err != nil {
		log.Printf("IP rule error for domain %s: %v", domain, err)
	}
}

func (s *DNSServer) matchCustomResolver(domain string) string {
	domain = strings.TrimSuffix(domain, ".")

	for _, rule := range s.customRules {
		if patterns.Match(rule.Pattern, domain) {
			return rule.Resolver
		}
	}
	return ""
}

func extractDomain(msg *dns.Msg) string {
	if len(msg.Question) > 0 {
		return strings.TrimSuffix(msg.Question[0].Name, ".")
	}
	return ""
}
