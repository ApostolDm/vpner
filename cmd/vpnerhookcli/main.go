package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/ApostolDmitry/vpner/internal/client"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/hookmeta"
)

func main() {
	var (
		cfgPath  string
		addr     string
		unixPath string
		password string
		family   string
		table    string
		timeout  time.Duration
	)

	flag.StringVar(&cfgPath, "config", "", "path to CLI config (default ~/.vpner.cnf)")
	flag.StringVar(&addr, "addr", "", "vpnerd TCP address")
	flag.StringVar(&unixPath, "unix", "", "vpnerd unix socket")
	flag.StringVar(&password, "password", "", "password for vpnerd")
	flag.StringVar(&family, "family", "", "iptables family to restore (v4/v6)")
	flag.StringVar(&table, "table", "", "iptables table that was flushed (nat/mangle)")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "RPC timeout")
	flag.Parse()

	family, err := hookmeta.NormalizeFamily(family)
	if err != nil {
		log.Fatalf("invalid family: %v", err)
	}

	table, err = hookmeta.NormalizeTable(table)
	if err != nil {
		log.Fatalf("invalid table: %v", err)
	}

	opts, err := client.ResolveOptions(client.Options{
		ConfigPath: cfgPath,
		Addr:       addr,
		Unix:       unixPath,
		Password:   password,
		Timeout:    timeout.String(),
	})
	if err != nil {
		log.Fatalf("resolve options: %v", err)
	}

	rt, err := client.NewRuntime(opts)
	if err != nil {
		log.Fatalf("dial vpnerd: %v", err)
	}
	defer rt.Close()

	ctx, cancel := rt.Context(opts.Timeout)
	defer cancel()
	ctx = hookmeta.AppendOutgoingContext(ctx, hookmeta.Scope{Family: family, Table: table})

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
