package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/ApostolDmitry/vpner/config"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type grpcInstance struct {
	network string
	address string
	server  *grpc.Server
	lis     net.Listener
}

type grpcListenerBuilder struct {
	cfg     config.GRPCConfig
	handler grpcpb.VpnerManagerServer
}

func newGRPCListenerBuilder(cfg config.GRPCConfig, handler grpcpb.VpnerManagerServer) grpcListenerBuilder {
	return grpcListenerBuilder{cfg: cfg, handler: handler}
}

func (b grpcListenerBuilder) Build() ([]*grpcInstance, error) {
	if b.handler == nil {
		return nil, fmt.Errorf("nil gRPC handler")
	}
	var result []*grpcInstance

	if b.cfg.TCP.Enabled {
		inst, err := newGRPCInstance("tcp", b.cfg.TCP.Address, b.cfg.TCP.Auth, b.cfg.Auth.Password, b.handler)
		if err != nil {
			return nil, err
		}
		result = append(result, inst)
	}

	if b.cfg.Unix.Enabled {
		inst, err := newGRPCInstance("unix", b.cfg.Unix.Path, false, b.cfg.Auth.Password, b.handler)
		if err != nil {
			return nil, err
		}
		result = append(result, inst)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no gRPC listeners configured")
	}
	return result, nil
}

func newGRPCInstance(network, addr string, authRequired bool, password string, handler grpcpb.VpnerManagerServer) (*grpcInstance, error) {
	if network == "unix" {
		_ = os.Remove(addr)
	}
	lis, err := net.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("listen error (%s): %w", network, err)
	}

	opts := []grpc.ServerOption{}
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
	g.server.GracefulStop()
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
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	vals := md.Get("authorization")
	return len(vals) > 0 && vals[0] == expected
}
