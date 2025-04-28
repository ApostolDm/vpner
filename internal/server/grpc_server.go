package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/ApostolDmitry/vpner/internal/dnsserver"
	"github.com/ApostolDmitry/vpner/internal/dohclient"
	pb "github.com/ApostolDmitry/vpner/internal/grpc"
	manager_interface "github.com/ApostolDmitry/vpner/internal/interface"
	"github.com/ApostolDmitry/vpner/internal/network"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type RunConfig struct {
	TCPEnabled       bool
	TCPAddress       string
	TCPAuthRequired  bool
	UnixEnabled      bool
	UnixPath         string
	UnixAuthRequired bool
	Password         string

	DNSConfig    dnsserver.ServerConfig
	ResolverConf dohclient.ResolverConfig
	UnblockPath  string
}

func RunServer(ctx context.Context, cfg RunConfig) error {
	resolver := dohclient.NewResolver(cfg.ResolverConf)

	iptablesManager := network.NewIptablesManager()

	unblock := network.NewUnblockManager(cfg.UnblockPath)
	if err := unblock.Init(); err != nil {
		return fmt.Errorf("failed to init unblock manager: %w", err)
	}

	ssManager := network.NewSsManager("", iptablesManager)
	if err := ssManager.Init(); err != nil {
		return fmt.Errorf("failed to init ss manager: %w", err)
	}

	dnsService := NewDNSService(cfg.DNSConfig, unblock, resolver)
	ssService := NewSSService(ssManager)

	if cfg.DNSConfig.Running {
		log.Println("Autostart DNS-server form config")
		if err := dnsService.Start(); err != nil {
			log.Printf("Error starting dns: %v", err)
		}
	}

	ifManager := manager_interface.NewInterfaceManager("")

	serverImpl := &VpnerServer{
		dns:       dnsService,
		ss:        ssService,
		unblock:   unblock,
		resolver:  resolver,
		ifManager: ifManager,
		ssManger:  ssManager,
		iptablesManager: iptablesManager,
	}

	var tcpServer, unixServer *grpc.Server
	errCh := make(chan error, 2)

	// TCP listener
	if cfg.TCPEnabled {
		s, lis, err := listenAndServe("tcp", cfg.TCPAddress, cfg.TCPAuthRequired, cfg.Password, serverImpl)
		if err != nil {
			return err
		}
		tcpServer = s
		go func() {
			errCh <- s.Serve(lis)
		}()
	}

	// Unix listener
	if cfg.UnixEnabled {
		_ = os.Remove(cfg.UnixPath)
		s, lis, err := listenAndServe("unix", cfg.UnixPath, cfg.UnixAuthRequired, cfg.Password, serverImpl)
		if err != nil {
			return err
		}
		unixServer = s
		go func() {
			errCh <- s.Serve(lis)
		}()
	}

	go func() {
		<-ctx.Done()
		log.Println("Signal Shutdown")

		if dnsService != nil {
			dnsService.Stop()
		}
		if tcpServer != nil {
			tcpServer.GracefulStop()
		}
		if unixServer != nil {
			unixServer.GracefulStop()
		}
	}()

	return <-errCh
}

func listenAndServe(network, addr string, useAuth bool, password string, handler pb.VpnerManagerServer) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen(network, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen error (%s): %w", network, err)
	}
	log.Printf("gRPC listening on %s (%s)", addr, network)

	opts := []grpc.ServerOption{}
	if useAuth {
		opts = append(opts,
			grpc.UnaryInterceptor(authInterceptor(password)),
			grpc.StreamInterceptor(streamAuthInterceptor(password)),
		)
	}

	s := grpc.NewServer(opts...)
	pb.RegisterVpnerManagerServer(s, handler)

	return s, lis, nil
}

func authInterceptor(password string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !checkAuth(ctx, password) {
			return nil, status.Error(codes.Unauthenticated, "invalid password")
		}
		return handler(ctx, req)
	}
}

func streamAuthInterceptor(password string) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !checkAuth(ss.Context(), password) {
			return status.Error(codes.Unauthenticated, "invalid password")
		}
		return handler(srv, ss)
	}
}

func checkAuth(ctx context.Context, expected string) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	vals := md.Get("authorization")
	return len(vals) > 0 && vals[0] == expected
}
