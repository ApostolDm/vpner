package agent

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/ApostolDmitry/vpner/internal/conf"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/logx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const gracefulStopTimeout = 5 * time.Second

type grpcInstance struct {
	network string
	address string
	server  *grpc.Server
	lis     net.Listener
}

type grpcListenerBuilder struct {
	cfg     conf.GRPCConfig
	handler grpcpb.VpnerManagerServer
}

func newGRPCListenerBuilder(cfg conf.GRPCConfig, handler grpcpb.VpnerManagerServer) grpcListenerBuilder {
	return grpcListenerBuilder{cfg: cfg, handler: handler}
}

func (b grpcListenerBuilder) Build() ([]*grpcInstance, error) {
	if b.handler == nil {
		return nil, fmt.Errorf("nil gRPC handler")
	}
	if b.cfg.TCP.Enabled && b.cfg.TCP.Auth && b.cfg.Auth.Password == "" {

		logx.Warnf("grpc.tcp.auth is enabled but grpc.auth.password is empty: all TCP clients will be rejected")
	}

	var result []*grpcInstance
	closeAll := func() {
		for _, inst := range result {
			inst.Stop()
		}
	}

	if b.cfg.TCP.Enabled {
		inst, err := newGRPCInstance("tcp", b.cfg.TCP.Address, b.cfg.TCP.Auth, b.cfg.Auth.Password, &b.cfg.TCP.TLS, b.handler)
		if err != nil {
			closeAll()
			return nil, err
		}
		result = append(result, inst)
	}

	if b.cfg.Unix.Enabled {
		inst, err := newGRPCInstance("unix", b.cfg.Unix.Path, false, b.cfg.Auth.Password, nil, b.handler)
		if err != nil {
			closeAll()
			return nil, err
		}
		result = append(result, inst)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no gRPC listeners configured")
	}
	return result, nil
}

func newGRPCInstance(network, addr string, authRequired bool, password string, tlsCfg *conf.GRPCTLSConfig, handler grpcpb.VpnerManagerServer) (*grpcInstance, error) {
	if network == "unix" {
		_ = os.Remove(addr)
	}
	lis, err := listenRestricted(network, addr)
	if err != nil {
		return nil, fmt.Errorf("listen error (%s): %w", network, err)
	}
	if network == "unix" {

		if err := os.Chmod(addr, 0600); err != nil {
			_ = lis.Close()
			return nil, fmt.Errorf("chmod unix socket: %w", err)
		}
	}

	var opts []grpc.ServerOption
	if creds, err := serverTLSCreds(network, tlsCfg); err != nil {
		_ = lis.Close()
		return nil, err
	} else if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	if authRequired {
		opts = append(opts,
			grpc.UnaryInterceptor(authInterceptor(password)),
			grpc.StreamInterceptor(streamAuthInterceptor(password)),
		)
	}

	s := grpc.NewServer(opts...)
	grpcpb.RegisterVpnerManagerServer(s, handler)

	return &grpcInstance{
		network: network,
		address: addr,
		server:  s,
		lis:     lis,
	}, nil
}

func listenRestricted(network, addr string) (net.Listener, error) {
	if network != "unix" {
		return net.Listen(network, addr)
	}
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	return net.Listen(network, addr)
}

func (g *grpcInstance) Serve() error {
	if err := g.server.Serve(g.lis); err != nil {
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	}
	return nil
}

func (g *grpcInstance) Stop() {
	if g == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		g.server.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(gracefulStopTimeout):
		g.server.Stop()
		<-done
	}
	_ = g.lis.Close()
	if g.network == "unix" {
		_ = os.Remove(g.address)
	}
}

func authInterceptor(password string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !checkAuth(ctx, password) {
			return nil, status.Error(codes.Unauthenticated, "invalid password")
		}
		return handler(ctx, req)
	}
}

func streamAuthInterceptor(password string) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !checkAuth(ss.Context(), password) {
			return status.Error(codes.Unauthenticated, "invalid password")
		}
		return handler(srv, ss)
	}
}

func checkAuth(ctx context.Context, expected string) bool {
	if expected == "" {

		return false
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(vals[0]), []byte(expected)) == 1
}

func serverTLSCreds(network string, cfg *conf.GRPCTLSConfig) (credentials.TransportCredentials, error) {
	if network != "tcp" || cfg == nil || cfg.Cert == "" || cfg.Key == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load gRPC TLS keypair: %w", err)
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if cfg.ClientCA != "" {
		pem, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("read gRPC client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("gRPC client CA %s contains no usable certificates", cfg.ClientCA)
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(tc), nil
}
