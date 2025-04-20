package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ApostolDmitry/vpner/config"
	"github.com/ApostolDmitry/vpner/internal/server"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/alecthomas/kingpin/v2"
)

var (
	app        = kingpin.New("vpnerd", "A deamon vpner")
	configFile = app.Flag("config", "config file vpner").Short('c').Default("/opt/etc/vpner/vpner.yaml").String()
)

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		cancel()
	}()

	if err := launchApp(ctx); err != nil {
		utils.LogErrorF("Ошибка запуска vpnerd: %s", err)
		os.Exit(1)
	}

}

func launchApp(ctx context.Context) error {
	cfg, err := config.LoadFullConfig(*configFile)
	if err != nil {
		return err
	}
	runCfg := server.RunConfig{
		TCPEnabled:   cfg.GRPC.TCP.Enabled,
		TCPAddress:   cfg.GRPC.TCP.Address,
		UnixEnabled:  cfg.GRPC.Unix.Enabled,
		UnixPath:     cfg.GRPC.Unix.Path,
		Password:     cfg.GRPC.Auth.Password,
		DNSConfig:    cfg.DNSServer,
		ResolverConf: cfg.DoH,
		UnblockPath:  cfg.UnblockRulesPath,
	}
	return server.RunServer(ctx, runCfg)
}
