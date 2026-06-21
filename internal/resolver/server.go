package resolver

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ApostolDmitry/vpner/internal/conf"
	"github.com/ApostolDmitry/vpner/internal/logx"
	"github.com/ApostolDmitry/vpner/internal/matcher"
	"github.com/miekg/dns"
)

const defaultCustomResolveTimeout = 3 * time.Second

type compiledResolverRule struct {
	Upstream string
	Pattern  string
}

type IPSyncer interface {
	SyncFromAnswers(domain string, ips []net.IP) error
}

type Server struct {
	config        conf.ServerConfig
	connSemaphore chan struct{}
	ipManager     IPSyncer
	customRules   []compiledResolverRule
	customTimeout time.Duration
	resolver      *Upstream
	cache         *answerCache
	limiter       *rateLimiter
	udpServer     *dns.Server
	tcpServer     *dns.Server
	notifyStarted func()
}

func NewServer(cfg conf.ServerConfig, ipManager IPSyncer, resolver *Upstream) *Server {
	s := &Server{
		config:        cfg,
		connSemaphore: make(chan struct{}, cfg.MaxConcurrentConn),
		ipManager:     ipManager,
		resolver:      resolver,
		customTimeout: defaultCustomResolveTimeout,
	}
	if cfg.CustomResolveTimeout > 0 {
		s.customTimeout = time.Duration(cfg.CustomResolveTimeout) * time.Second
	}
	if cfg.Cache == nil || *cfg.Cache {
		s.cache = newAnswerCache(cfg.CacheMaxEntries)
	}
	if cfg.RateLimit > 0 {
		s.limiter = newRateLimiter(cfg.RateLimit)
	}

	for resolverAddr, entries := range cfg.CustomResolve {
		for _, raw := range entries {
			if err := matcher.Validate(raw); err != nil {
				logx.Errorf("invalid customResolve pattern %q: %v", raw, err)
				continue
			}
			s.customRules = append(s.customRules, compiledResolverRule{
				Upstream: resolverAddr,
				Pattern:  raw,
			})
		}
	}
	return s
}

func (s *Server) Run(ctx context.Context) error {
	dns.HandleFunc(".", s.handleDNSRequest)

	addr := s.config.Listen
	if addr == "" {
		addr = ":" + strconv.Itoa(s.config.Port)
	}
	s.udpServer = &dns.Server{Addr: addr, Net: "udp"}
	s.tcpServer = &dns.Server{Addr: addr, Net: "tcp"}
	if s.notifyStarted != nil {
		s.udpServer.NotifyStartedFunc = s.notifyStarted
	}

	go func() {
		<-ctx.Done()
		logx.Debugf("DNS server shutdown initiated")
		if err := s.udpServer.Shutdown(); err != nil {
			logx.Debugf("DNS udp shutdown: %v", err)
		}
		if err := s.tcpServer.Shutdown(); err != nil {
			logx.Debugf("DNS tcp shutdown: %v", err)
		}
	}()

	logx.Infof("DNS server starting on port %d", s.config.Port)
	go func() {
		if err := s.tcpServer.ListenAndServe(); err != nil {
			logx.Warnf("TCP DNS server exited: %v", err)
		}
	}()
	return s.udpServer.ListenAndServe()
}

func (s *Server) SetNotifyStartedFunc(fn func()) {
	s.notifyStarted = fn
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	responded := false
	reply := func(m *dns.Msg) {
		responded = true
		if err := w.WriteMsg(m); err != nil {
			logx.Debugf("DNS write failed: %v", err)
		}
	}
	servfail := func() {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		reply(m)
	}

	defer func() {
		if rec := recover(); rec != nil {
			logx.Errorf("panic in DNS handler: %v", rec)
			if !responded {
				servfail()
			}
		}
	}()

	var questions, source string
	if s.config.Verbose {
		questions = formatQuestions(r)
		source = formatRemoteAddr(w)
		logx.Infof("DNS query from %s: %s", source, questions)
	}

	if s.limiter != nil && !s.limiter.allow(formatRemoteAddr(w)) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		reply(m)
		return
	}

	domain := extractDomain(r)

	if s.cache != nil {
		if cached := s.cache.get(r); cached != nil {
			reply(cached)
			if domain != "" {
				go s.processDomainAnswers(domain, cached)
			}
			return
		}
	}

	select {
	case s.connSemaphore <- struct{}{}:
		defer func() { <-s.connSemaphore }()
	default:
		logx.Warnf("DNS server overloaded, dropping query")
		servfail()
		return
	}

	if resolverIP := s.matchCustomResolver(domain); resolverIP != "" {
		if s.config.Verbose {
			logx.Infof("Domain %s resolved via custom %s", domain, resolverIP)
		}
		client := &dns.Client{Net: "udp", Timeout: s.customTimeout}
		resp, _, err := client.Exchange(r.Copy(), resolverIP)
		if err != nil {
			logx.Warnf("custom resolver %s error: %v", resolverIP, err)
			servfail()
			return
		}
		resp.Id = r.Id
		if s.cache != nil {
			s.cache.put(resp)
		}
		reply(resp)
		if s.config.Verbose {
			logx.Infof("DNS response to %s for %s (custom %s, %s): %s",
				source, questions, resolverIP, formatRcode(resp), formatAnswers(resp))
		}
		if domain != "" {
			go s.processDomainAnswers(domain, resp)
		}
		return
	}

	packed, err := r.Pack()
	if err != nil {
		logx.Warnf("DNS pack error: %v", err)
		servfail()
		return
	}

	resp, err := s.resolver.ForwardQuery(packed)
	if err != nil {
		logx.Warnf("DoH forward error: %v", err)
		servfail()
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		logx.Warnf("DNS unpack error: %v", err)
		servfail()
		return
	}
	msg.Id = r.Id
	if s.cache != nil {
		s.cache.put(msg)
	}
	reply(msg)
	if s.config.Verbose {
		logx.Infof("DNS response to %s for %s (%s): %s",
			source, questions, formatRcode(msg), formatAnswers(msg))
	}
	if domain != "" {
		go s.processDomainAnswers(domain, msg)
	}
}

func (s *Server) processDomainAnswers(domain string, msg *dns.Msg) {
	if s.ipManager == nil || msg == nil {
		return
	}
	ips := extractIPs(msg)
	if len(ips) == 0 {
		return
	}
	if err := s.ipManager.SyncFromAnswers(domain, ips); err != nil {
		logx.Warnf("IP rule sync error for domain %s: %v", domain, err)
	}
}

func (s *Server) matchCustomResolver(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	for _, rule := range s.customRules {
		if matcher.Match(rule.Pattern, domain) {
			return rule.Upstream
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
	if code := dns.RcodeToString[msg.Rcode]; code != "" {
		return code
	}
	return fmt.Sprintf("RCODE%d", msg.Rcode)
}

func formatRemoteAddr(w dns.ResponseWriter) string {
	if w == nil {
		return "unknown"
	}
	addr := w.RemoteAddr()
	if addr == nil {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil && host != "" {
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
