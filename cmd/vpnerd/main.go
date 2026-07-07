package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ApostolDmitry/vpner/internal/agent"
	"github.com/ApostolDmitry/vpner/internal/backup"
	"github.com/ApostolDmitry/vpner/internal/buildinfo"
	"github.com/ApostolDmitry/vpner/internal/conf"
	"github.com/ApostolDmitry/vpner/internal/logsyslog"
	"github.com/ApostolDmitry/vpner/internal/logx"
)

func main() {
	var configFile, logLevel, logFile, backupFile, restoreFile string
	var logMaxKB, logBackups int
	var showVersion bool
	flag.StringVar(&configFile, "config", "/opt/etc/vpner/vpner.yaml", "config file path")
	flag.StringVar(&configFile, "c", "/opt/etc/vpner/vpner.yaml", "config file path (shorthand)")
	flag.StringVar(&logLevel, "log-level", "info", "log level: error, warn, info, debug")
	flag.StringVar(&logFile, "log-file", "", "write logs to this file with size-based rotation (default: syslog)")
	flag.IntVar(&logMaxKB, "log-max-kb", 1024, "rotate log file once it reaches this size in KiB")
	flag.IntVar(&logBackups, "log-backups", 3, "number of rotated log files to keep")
	flag.StringVar(&backupFile, "backup", "", "archive the state directory to this file and exit")
	flag.StringVar(&restoreFile, "restore", "", "restore the state directory from this archive and exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("vpnerd", buildinfo.String())
		return
	}

	stateDir := filepath.Dir(configFile)
	if backupFile != "" {
		if err := backup.Create(stateDir, backupFile); err != nil {
			fmt.Fprintln(os.Stderr, "backup failed:", err)
			os.Exit(1)
		}
		fmt.Printf("backup written to %s\n", backupFile)
		return
	}
	if restoreFile != "" {
		if err := backup.Restore(restoreFile, stateDir); err != nil {
			fmt.Fprintln(os.Stderr, "restore failed:", err)
			os.Exit(1)
		}
		fmt.Printf("state restored into %s; restart vpnerd to apply\n", stateDir)
		return
	}

	logx.SetLevel(logLevel)
	if logFile != "" {
		if err := logsyslog.ConfigureFile(logFile, logMaxKB, logBackups); err != nil {
			logx.Warnf("log file unavailable, using stderr fallback: %v", err)
		}
	} else if err := logsyslog.Configure(); err != nil {
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				logx.Infof("SIGHUP received, reloading")
				rt.Reload(configFile)
			}
		}
	}()

	err = rt.Run(ctx)
	cancel()
	<-done
	return err
}
