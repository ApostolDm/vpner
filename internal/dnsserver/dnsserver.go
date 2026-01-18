package dnsserver

import (
	"fmt"
	"log"
	"net"
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
	udpServer      *dns.Server
	tcpServer      *dns.Server
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
	s.udpServer = &dns.Server{Addr: addr, Net: "udp"}
	s.tcpServer = &dns.Server{Addr: addr, Net: "tcp"}
	if s.notifyStarted != nil {
		s.udpServer.NotifyStartedFunc = s.notifyStarted
	}

	go func() {
		<-ctx.Done()
		if s.config.Verbose {
			log.Println("DNS server shutdown initiated")
		}
		_ = s.udpServer.Shutdown()
		_ = s.tcpServer.Shutdown()
	}()

	if s.config.Verbose {
		log.Printf("Starting DNS server on port %d...", s.config.Port)
	}

	go func() {
		if err := s.tcpServer.ListenAndServe(); err != nil {
			log.Printf("TCP DNS server exited: %v", err)
		}
	}()

	return s.udpServer.ListenAndServe()
}

func (s *DNSServer) SetNotifyStartedFunc(fn func()) {
	s.notifyStarted = fn
}

func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	var questions string
	var source string
	if s.config.Verbose {
		questions = formatQuestions(r)
		source = formatRemoteAddr(w)
		log.Printf("DNS query from %s: %s", source, questions)
	}

	s.connSemaphore <- struct{}{}
	defer func() { <-s.connSemaphore }()

	domain := extractDomain(r)

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
		if s.config.Verbose {
			log.Printf("DNS response to %s for %s (custom %s, %s): %s", source, questions, resolverIP, formatRcode(resp), formatAnswers(resp))
		}
		if domain != "" {
			go s.processDomainAnswers(domain, resp)
		}
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
	if s.config.Verbose {
		log.Printf("DNS response to %s for %s (%s): %s", source, questions, formatRcode(msg), formatAnswers(msg))
	}
	if domain != "" {
		go s.processDomainAnswers(domain, msg)
	}
}

func (s *DNSServer) processDomainAnswers(domain string, msg *dns.Msg) {
	if msg == nil {
		return
	}
	ips := extractIPs(msg)
	if len(ips) == 0 {
		return
	}
	manager := network.NewIpRuleManager(s.unblockManager, s.resolver)
	if err := manager.SyncFromAnswers(domain, ips); err != nil {
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

func formatQuestions(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return "unknown"
	}
	items := make([]string, 0, len(msg.Question))
	for _, question := range msg.Question {
		name := strings.TrimSuffix(question.Name, ".")
		if name == "" {
			name = "."
		}
		qtype := dns.TypeToString[question.Qtype]
		if qtype == "" {
			qtype = fmt.Sprintf("TYPE%d", question.Qtype)
		}
		items = append(items, fmt.Sprintf("%s %s", name, qtype))
	}
	return strings.Join(items, ", ")
}

func formatAnswers(msg *dns.Msg) string {
	if msg == nil || len(msg.Answer) == 0 {
		return "no answers"
	}
	answers := make([]string, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		answers = append(answers, rr.String())
	}
	return strings.Join(answers, "; ")
}

func formatRcode(msg *dns.Msg) string {
	if msg == nil {
		return "unknown"
	}
	code := dns.RcodeToString[msg.Rcode]
	if code == "" {
		return fmt.Sprintf("RCODE%d", msg.Rcode)
	}
	return code
}

func formatRemoteAddr(w dns.ResponseWriter) string {
	if w == nil {
		return "unknown"
	}
	addr := w.RemoteAddr()
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil && host != "" {
		return host
	}
	return addr.String()
}

func extractIPs(msg *dns.Msg) []net.IP {
	if msg == nil {
		return nil
	}
	ips := make([]net.IP, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if record.A != nil {
				ips = append(ips, record.A)
			}
		case *dns.AAAA:
			if record.AAAA != nil {
				ips = append(ips, record.AAAA)
			}
		}
	}
	return ips
}
