package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"gopkg.in/yaml.v3"
)

type options struct {
	ConfigPath string
	Addr       string
	Unix       string
	Password   string
}

type resolvedOptions struct {
	Addr     string
	Unix     string
	Password string
}

type fileConfig struct {
	Addr     string `yaml:"addr"`
	Unix     string `yaml:"unix"`
	Password string `yaml:"password"`
}

func main() {
	var (
		cfgPath  string
		addr     string
		unixPath string
		password string
		family   string
		timeout  time.Duration
	)

	flag.StringVar(&cfgPath, "config", "", "path to CLI config (default ~/.vpner.cnf)")
	flag.StringVar(&addr, "addr", "", "vpnerd TCP address")
	flag.StringVar(&unixPath, "unix", "", "vpnerd unix socket")
	flag.StringVar(&password, "password", "", "password for vpnerd")
	flag.StringVar(&family, "family", "", "iptables family to restore (v4/v6)")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "RPC timeout")
	flag.Parse()

	family, err := normalizeFamily(family)
	if err != nil {
		log.Fatalf("invalid family: %v", err)
	}

	opts, err := resolveOptions(options{
		ConfigPath: cfgPath,
		Addr:       addr,
		Unix:       unixPath,
		Password:   password,
	})
	if err != nil {
		log.Fatalf("resolve options: %v", err)
	}

	rt, err := newRuntime(opts)
	if err != nil {
		log.Fatalf("dial vpnerd: %v", err)
	}
	defer rt.Close()

	ctx, cancel := rt.Context(timeout)
	defer cancel()
	if family != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "hook-family", family)
	}

	resp, err := rt.Client().HookRestore(ctx, &grpcpb.Empty{})
	if err != nil {
		log.Fatalf("hook restore failed: %v", err)
	}

	if success := resp.GetSuccess(); success != nil {
		fmt.Println(success.Message)
		return
	}
	if failure := resp.GetError(); failure != nil {
		log.Fatalf("hook restore error: %s", failure.Message)
	}
}

func resolveOptions(opts options) (resolvedOptions, error) {
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cfgPath = filepath.Join(home, ".vpner.cnf")
		}
	}

	var fileCfg *fileConfig
	if cfgPath != "" {
		cfg, err := readConfig(cfgPath)
		if err != nil {
			return resolvedOptions{}, err
		}
		fileCfg = cfg
	}

	resolved := resolvedOptions{
		Addr:     opts.Addr,
		Unix:     opts.Unix,
		Password: opts.Password,
	}

	if resolved.Addr == "" && fileCfg != nil && fileCfg.Addr != "" {
		resolved.Addr = fileCfg.Addr
	}
	if resolved.Unix == "" && fileCfg != nil && fileCfg.Unix != "" {
		resolved.Unix = fileCfg.Unix
	}
	if resolved.Password == "" && fileCfg != nil && fileCfg.Password != "" {
		resolved.Password = fileCfg.Password
	}

	if resolved.Addr == "" && resolved.Unix == "" {
		resolved.Unix = "/tmp/vpner.sock"
	}
	if resolved.Addr == "" {
		resolved.Addr = ":50051"
	}

	return resolved, nil
}

func readConfig(path string) (*fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg fileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

type rpcRuntime struct {
	conn     *grpc.ClientConn
	client   grpcpb.VpnerManagerClient
	password string
}

func newRuntime(opts resolvedOptions) (*rpcRuntime, error) {
	target := dialTarget(opts)
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &rpcRuntime{
		conn:     conn,
		client:   grpcpb.NewVpnerManagerClient(conn),
		password: opts.Password,
	}, nil
}

func dialTarget(opts resolvedOptions) string {
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

func (r *rpcRuntime) Client() grpcpb.VpnerManagerClient {
	return r.client
}

func (r *rpcRuntime) Context(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	if r.password != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", r.password))
	}
	return ctx, cancel
}

func (r *rpcRuntime) Close() {
	if r.conn != nil {
		_ = r.conn.Close()
	}
}

func normalizeFamily(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", nil
	case "v4", "ipv4", "iptables":
		return "ipv4", nil
	case "v6", "ipv6", "ip6tables":
		return "ipv6", nil
	default:
		return "", fmt.Errorf("unsupported family %q", value)
	}
}
