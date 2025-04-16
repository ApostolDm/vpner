package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/ApostolDmitry/vpner/config"
	"github.com/ApostolDmitry/vpner/internal/common/logging"
	appruntime "github.com/ApostolDmitry/vpner/internal/runtime"
	"github.com/alecthomas/kingpin/v2"
)

var (
	cliApp     = kingpin.New("vpnerd", "A deamon vpner")
	configFile = cliApp.Flag("config", "config file vpner").Short('c').Default("/opt/etc/vpner/vpner.yaml").String()
	logLevel   = cliApp.Flag("log-level", "Log level: error, warn, info, debug").Default("info").String()
)

func main() {
	kingpin.MustParse(cliApp.Parse(os.Args[1:]))
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	logging.SetLevel(*logLevel)
	logging.Infof("Starting vpnerd, config=%s", *configFile)

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		cancel()
	}()

	if err := launchApp(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			logging.Infof("vpnerd stopped by context cancel")
			return
		}
		logging.Errorf("Ошибка запуска vpnerd: %s", err)
		os.Exit(1)
	}

}

func launchApp(ctx context.Context) error {
	cfg, err := config.LoadFullConfig(*configFile)
	if err != nil {
		return err
	}
	rt, err := appruntime.New(*cfg)
	if err != nil {
		return err
	}
	return rt.Run(ctx)
}
