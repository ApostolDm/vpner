package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/ApostolDmitry/vpner/internal/buildinfo"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/hookscope"
	"github.com/ApostolDmitry/vpner/internal/rpcclient"
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
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("vpnerhookcli", buildinfo.String())
		return
	}

	family, err := hookscope.NormalizeFamily(family)
	if err != nil {
		log.Fatalf("invalid family: %v", err)
	}

	table, err = hookscope.NormalizeTable(table)
	if err != nil {
		log.Fatalf("invalid table: %v", err)
	}

	opts, err := rpcclient.ResolveOptions(rpcclient.Options{
		ConfigPath: cfgPath,
		Addr:       addr,
		Unix:       unixPath,
		Password:   password,
		Timeout:    timeout.String(),
	})
	if err != nil {
		log.Fatalf("resolve options: %v", err)
	}

	rt, err := rpcclient.NewRuntime(opts)
	if err != nil {
		log.Fatalf("dial vpnerd: %v", err)
	}
	defer rt.Close()

	ctx, cancel := rt.Context(opts.Timeout)
	defer cancel()
	ctx = hookscope.AppendOutgoingContext(ctx, hookscope.Scope{Family: family, Table: table})

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
