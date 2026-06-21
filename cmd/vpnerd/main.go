package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := launchApp(ctx, configFile); err != nil {
		if errors.Is(err, context.Canceled) {
			logx.Infof("vpnerd stopped by context cancel")
			return
		}
		logx.Errorf("vpnerd startup error: %s", err)
		os.Exit(1)
	}
}

func launchApp(ctx context.Context, configFile string) error {
	cfg, err := conf.LoadFullConfig(configFile)
	if err != nil {
		return err
	}
	rt, err := agent.New(*cfg)
	if err != nil {
		return err
	}
	return rt.Run(ctx)
}
