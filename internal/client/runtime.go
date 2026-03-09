package client

import (
	"context"
	"fmt"
	"strings"
	"time"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Runtime struct {
	conn     *grpc.ClientConn
	client   grpcpb.VpnerManagerClient
	password string
	target   string
}

func NewRuntime(opts ResolvedOptions) (*Runtime, error) {
	target := dialTarget(opts)
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	return &Runtime{
		conn:     conn,
		client:   grpcpb.NewVpnerManagerClient(conn),
		password: opts.Password,
		target:   target,
	}, nil
}

func dialTarget(opts ResolvedOptions) string {
	if opts.Unix != "" {
		if strings.HasPrefix(opts.Unix, "unix://") {
			return opts.Unix
		}
		return "unix://" + opts.Unix
	}
	if strings.HasPrefix(opts.Addr, "unix://") {
		return opts.Addr
	}
	return opts.Addr
}

func (r *Runtime) Client() grpcpb.VpnerManagerClient {
	return r.client
}

func (r *Runtime) Context(timeout time.Duration) (context.Context, context.CancelFunc) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	if r.password != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", r.password))
	}
	return ctx, cancel
}

func (r *Runtime) Close() {
	if r.conn != nil {
		_ = r.conn.Close()
	}
}
