package dnsserver

import (
	"log"
	"strconv"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/dohclient"
	"github.com/ApostolDmitry/vpner/internal/network"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/miekg/dns"
)

type ServerConfig struct {
	Port              int
	MaxConcurrentConn int
	Verbose           bool
	CustomResolve     map[string][]string
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
}

func NewDNSServer(cfg ServerConfig, um *network.UnblockManager, resolver *dohclient.Resolver) *DNSServer {
	s := &DNSServer{
		config:         cfg,
		connSemaphore:  make(chan struct{}, cfg.MaxConcurrentConn),
		unblockManager: um,
		resolver:       resolver,
	}

	for resolverAddr, patterns := range cfg.CustomResolve {
		for _, raw := range patterns {
			if err := utils.ValidatePattern(raw); err != nil {
				log.Printf("ошибка в шаблоне customResolve %q: %v", raw, err)
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

func (s *DNSServer) Run() {
	dns.HandleFunc(".", s.handleDNSRequest)
	server := &dns.Server{Addr: ":" + strconv.Itoa(s.config.Port), Net: "udp"}

	if s.config.Verbose {
		log.Printf("Starting DNS server on port %d...", s.config.Port)
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
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

		in := new(dns.Msg)
		in.SetQuestion(domain, dns.TypeA)
		resp, err := dns.Exchange(in, resolverIP)
		if err != nil {
			log.Printf("Custom resolver error: %v", err)
			return
		}
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
	manager := network.NewIpRuleManager("", s.unblockManager, s.resolver)
	if err := manager.CheckIPsInIpset(domain); err != nil {
		log.Printf("IP rule error for domain %s: %v", domain, err)
	}
}

func (s *DNSServer) matchCustomResolver(domain string) string {
	domain = strings.TrimSuffix(domain, ".")

	for _, rule := range s.customRules {
		if utils.MatchWildcard(rule.Pattern, domain) {
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
