package rpc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	firewall "github.com/ApostolDmitry/vpner/internal/firewall"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/logx"
	netif "github.com/ApostolDmitry/vpner/internal/netif"
	"github.com/ApostolDmitry/vpner/internal/vpnkind"
	"gopkg.in/yaml.v3"
)

const DefaultRouteFileName = "vpner_default_route.yaml"

const xrayRestartGrace = 30 * time.Second

type defaultRoute struct {
	Type  string `yaml:"type"`
	Chain string `yaml:"chain"`
}

func (d defaultRoute) set() bool { return d.Type != "" && d.Chain != "" }

func loadDefaultRoute(path string) (defaultRoute, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return defaultRoute{}, nil
	}
	if err != nil {
		return defaultRoute{}, err
	}
	var d defaultRoute
	if err := yaml.Unmarshal(data, &d); err != nil {
		return defaultRoute{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if !d.set() {
		return defaultRoute{}, nil
	}
	return d, nil
}

func saveDefaultRoute(path string, d defaultRoute) error {
	if !d.set() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data, err := yaml.Marshal(d)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *VpnerServer) defaultRoute() defaultRoute {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	return s.route
}

func (s *VpnerServer) setRoute(d defaultRoute) {
	s.routeMu.Lock()
	s.route = d
	s.routeMu.Unlock()
}

func (s *VpnerServer) isDefaultRoute(vpnType, chain string) bool {
	d := s.defaultRoute()
	return d.set() && d.Type == vpnType && d.Chain == chain
}

func (s *VpnerServer) targetExists(d defaultRoute) bool {
	if d.Type == vpnkind.Xray.String() {
		return s.xrayService.IsChain(d.Chain)
	}
	typ, ok := s.ifManager.LookupTrackedType(d.Chain)
	return ok && typ == d.Type
}

func (s *VpnerServer) armDefaultRoute(d defaultRoute) ([]string, error) {
	ipsetName, err := firewall.IpsetName(d.Type, d.Chain)
	if err != nil {
		return nil, err
	}
	return s.iptables.SetDefaultTarget(vpnkind.Kind(d.Type), ipsetName)
}

func (s *VpnerServer) LoadDefaultRoute() {
	d, err := loadDefaultRoute(s.routeFile)
	if err != nil {
		logx.Warnf("default route state: %v", err)
		return
	}
	if !d.set() {
		return
	}
	s.setRoute(d)
	if !s.targetExists(d) {
		logx.Warnf("default route target %s/%s not found; run 'vpnerctl route split' or 'vpnerctl route all <chain>'", d.Type, d.Chain)
	}
	warnings, err := s.armDefaultRoute(d)
	for _, w := range warnings {
		logx.Warnf("default route: %s", w)
	}
	if err != nil && !errors.Is(err, firewall.ErrDefaultRoutePending) {
		logx.Errorf("default route via %s: %v", d.Chain, err)
	}
	logx.Infof("default route: all LAN traffic via %s (%s)", d.Chain, d.Type)
}

func (s *VpnerServer) RefreshDefaultRoute() {
	s.iptables.RefreshDefaultRoute()
}

func (s *VpnerServer) SetDefaultRoute(_ context.Context, req *grpcpb.DefaultRouteRequest) (*grpcpb.GenericResponse, error) {
	s.routeOpMu.Lock()
	defer s.routeOpMu.Unlock()

	if req.ChainName == "" {
		return s.clearDefaultRoute()
	}
	chain := req.ChainName
	vpnType, ok := s.resolveChainType(chain)
	if !ok {
		return errorGeneric(fmt.Sprintf("Failed to set default route: chain %q does not exist", chain)), nil
	}
	router := vpnkind.IsRouterManaged(vpnType)
	prev := s.defaultRoute()
	next := defaultRoute{Type: vpnType, Chain: chain}

	var pending string
	if router {
		if err := s.applyMarkRouting(vpnType, chain); err != nil {
			if !errors.Is(err, netif.ErrInterfaceDown) {
				return errorGeneric(fmt.Sprintf("Failed to configure routing for %s: %v", chain, err)), nil
			}
			pending = fmt.Sprintf("interface %s is down, it activates when the interface comes up", chain)
		}
	} else {
		s.xrayMu.Lock()
		running := s.xrayService.IsRunning(chain)
		var applyErr error
		if running {
			applyErr = s.applyXrayRouting(chain)
		}
		s.xrayMu.Unlock()
		if applyErr != nil {
			return errorGeneric(fmt.Sprintf("Failed to configure routing for %s: %v", chain, applyErr)), nil
		}
		if !running {
			pending = fmt.Sprintf("xray %s is stopped, it activates when the chain starts", chain)
		}
	}

	restorePrev := func() {
		if prev.set() {
			_, _ = s.armDefaultRoute(prev)
		} else {
			s.iptables.ClearDefaultTarget()
		}
		if router && prev != next {
			_ = s.dropMarkRoutingIfUnused(vpnType, chain)
		}
	}
	warnings, err := s.armDefaultRoute(next)
	if err != nil && !errors.Is(err, firewall.ErrDefaultRoutePending) {
		restorePrev()
		return errorGeneric(fmt.Sprintf("Failed to configure default route: %v", err)), nil
	}
	if err := saveDefaultRoute(s.routeFile, next); err != nil {
		restorePrev()
		return errorGeneric(fmt.Sprintf("Failed to save default route: %v", err)), nil
	}
	s.setRoute(next)
	if prev.set() && prev != next && vpnkind.IsRouterManaged(prev.Type) {
		if err := s.dropMarkRoutingIfUnused(prev.Type, prev.Chain); err != nil {
			logx.Warnf("default route: release previous target %s: %v", prev.Chain, err)
		}
	}

	var lines []string
	switch {
	case pending != "":
		lines = append(lines, fmt.Sprintf("Default route saved: %s", pending))
	case err != nil:
		lines = append(lines, fmt.Sprintf("Default route saved: %v", err))
	default:
		lines = append(lines, fmt.Sprintf("Default route: all LAN traffic via %s (%s)", chain, vpnType))
	}
	for _, w := range warnings {
		lines = append(lines, "Warning: "+w)
	}
	if !router {
		if !s.info.TProxyEnabled {
			lines = append(lines, "Note: REDIRECT mode is TCP-only; UDP (QUIC, DNS to external resolvers) still bypasses the tunnel")
		}
		if info, err := s.xrayService.GetInfo(chain); err == nil && !info.AutoRun {
			lines = append(lines, fmt.Sprintf("Note: autorun is off, the default route will not survive a reboot (vpnerctl xray autorun %s --enable)", chain))
		}
	}
	return successGeneric(strings.Join(lines, "\n")), nil
}

func (s *VpnerServer) clearDefaultRoute() (*grpcpb.GenericResponse, error) {
	prev := s.defaultRoute()
	if !prev.set() {
		return successGeneric("Default route is not set: per-rule routing is active"), nil
	}
	s.setRoute(defaultRoute{})
	s.iptables.ClearDefaultTarget()
	if vpnkind.IsRouterManaged(prev.Type) {
		if err := s.dropMarkRoutingIfUnused(prev.Type, prev.Chain); err != nil {
			logx.Warnf("default route: release %s: %v", prev.Chain, err)
		}
	}
	if err := saveDefaultRoute(s.routeFile, defaultRoute{}); err != nil {
		return errorGeneric(fmt.Sprintf("Default route disabled, but the state file was not updated (it returns after a restart): %v", err)), nil
	}
	return successGeneric("Default route disabled: per-rule routing is active"), nil
}

func (s *VpnerServer) defaultRouteStatus() *grpcpb.DefaultRouteStatus {
	d := s.defaultRoute()
	st := &grpcpb.DefaultRouteStatus{}
	if !d.set() {
		return st
	}
	st.ChainName, st.Type = d.Chain, d.Type
	if !s.targetExists(d) {
		st.Reason = fmt.Sprintf("target %s not found (deleted?), run 'vpnerctl route split'", d.Chain)
		return st
	}
	applied := s.iptables.DefaultRouteApplied()
	routeErr := s.iptables.DefaultRouteError()
	if vpnkind.IsRouterManaged(d.Type) {
		ipsetName, _ := firewall.IpsetName(d.Type, d.Chain)
		switch {
		case !s.iptables.MarkRouteKnown(ipsetName):
			st.Reason = fmt.Sprintf("interface %s is down, LAN traffic is using the WAN", d.Chain)
		case routeErr != "":
			st.Reason = "not applied: " + routeErr
		case !applied:
			st.Reason = "not applied yet"
		case !s.iptables.MarkIntact(d.Type, d.Chain):
			st.Reason = fmt.Sprintf("interface %s lost its route, LAN traffic is using the WAN", d.Chain)
		}
	} else {
		rt := s.xrayService.Runtimes()[d.Chain]
		switch {
		case !s.xrayService.IsRunning(d.Chain):
			st.Reason = fmt.Sprintf("xray %s is stopped", d.Chain)
			if info, err := s.xrayService.GetInfo(d.Chain); err == nil && !info.AutoRun {
				st.Reason += fmt.Sprintf(" (autorun is off, it will not start at boot: vpnerctl xray autorun %s --enable)", d.Chain)
			}
		case rt.Restarts > 0 && rt.Uptime < xrayRestartGrace:
			st.Reason = fmt.Sprintf("xray %s is restarting (%d restarts, last exit: %s), LAN traffic is dropped until it is back", d.Chain, rt.Restarts, rt.LastExit)
		case routeErr != "":
			st.Reason = "not applied: " + routeErr
		case !applied:
			st.Reason = "not applied yet"
		}
	}
	st.Active = st.Reason == ""
	return st
}
