package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/ApostolDmitry/vpner/internal/agent"
	"github.com/ApostolDmitry/vpner/internal/buildinfo"
	"github.com/ApostolDmitry/vpner/internal/conf"
	"github.com/ApostolDmitry/vpner/internal/logsyslog"
	"github.com/ApostolDmitry/vpner/internal/logx"
)

func main() {
	var configFile, logLevel string
	var showVersion bool
	flag.StringVar(&configFile, "config", "/opt/etc/vpner/vpner.yaml", "config file path")
	flag.StringVar(&configFile, "c", "/opt/etc/vpner/vpner.yaml", "config file path (shorthand)")
	flag.StringVar(&logLevel, "log-level", "info", "log level: error, warn, info, debug")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("vpnerd", buildinfo.String())
		return
	}

	logx.SetLevel(logLevel)
	if err := logsyslog.Configure(); err != nil {
		logx.Warnf("syslog unavailable, using stderr fallback: %v", err)
	}
	logx.Infof("Starting vpnerd, config=%s", configFile)
	raiseOpenFilesLimit()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, configFile); err != nil {
		if errors.Is(err, context.Canceled) {
			logx.Infof("vpnerd stopped by context cancel")
			return
		}
		logx.Errorf("vpnerd startup error: %s", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configFile string) error {
	cfg, err := conf.LoadFullConfig(configFile)
	if err != nil {
		return err
	}
	if err := conf.CheckKnownFields(configFile); err != nil {
		logx.Warnf("config: %v", err)
	}
	applyRuntimeLimits(cfg.Runtime)

	rt, err := agent.New(*cfg)
	if err != nil {
		return err
	}
	return rt.Run(ctx)
}

func applyRuntimeLimits(rc conf.RuntimeConfig) {
	if rc.GCPercent > 0 && os.Getenv("GOGC") == "" {
		debug.SetGCPercent(rc.GCPercent)
	}
	if rc.MemoryLimitMB > 0 && os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(int64(rc.MemoryLimitMB) << 20)
	}
}
