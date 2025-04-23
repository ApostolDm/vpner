package cmd

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var (
	configPath string
	grpcAddr   string
	unixPath   string
	password   string

	config *CLIConfig
	conn   *grpc.ClientConn
	ctx    context.Context
	cancel context.CancelFunc

	rootCmd = &cobra.Command{
		Use:   "vpner-cli",
		Short: "CLI для управления vpnerd",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			config, _ = loadCLIConfig(configPath)

			addr, unix, pass := resolveConnectionOptions(config)

			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			if pass != "" {
				ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", pass))
			}

			conn, err = dialGRPC(addr, unix)
			return err
		},
	}
)

func Execute() {
	defer func() {
		if cancel != nil {
			cancel()
		}
		if conn != nil {
			_ = conn.Close()
		}
	}()
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Путь к конфигу (по умолчанию ~/.vpner.cnf)")
	rootCmd.PersistentFlags().StringVar(&grpcAddr, "addr", "", "TCP адрес сервера")
	rootCmd.PersistentFlags().StringVar(&unixPath, "unix", "", "Unix-сокет")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "Пароль")

	//DNS
	rootCmd.AddCommand(dnsCmd)
	//unblock
	unblockCmd.AddCommand(unblockListCmd)
	unblockCmd.AddCommand(UnblockAddCmd())
	unblockCmd.AddCommand(UnblockDelCmd())
	rootCmd.AddCommand(unblockCmd)
	//interface
	interfaceCmd.AddCommand(InterfaceListCmd())
	interfaceCmd.AddCommand(InterfaceScanCmd())
	rootCmd.AddCommand(interfaceCmd)
	// ss
	ssCmd.AddCommand(ssNewCmd())
	ssCmd.AddCommand(ssListCmd())
	ssCmd.AddCommand(ssDelCmd())
	ssCmd.AddCommand(ssManageCmd())
	rootCmd.AddCommand(ssCmd)
}

func resolveConnectionOptions(cfg *CLIConfig) (addr, unix, pass string) {
	addr = grpcAddr
	unix = unixPath
	pass = password

	if cfg != nil {
		if addr == "" && cfg.Addr != "" {
			addr = cfg.Addr
		}
		if unix == "" && cfg.Unix != "" {
			unix = cfg.Unix
		}
		if pass == "" && cfg.Password != "" {
			pass = cfg.Password
		}
	}

	if addr == "" && unix == "" {
		unix = "/tmp/vpner.sock"
	}
	return
}

func dialGRPC(addr, unix string) (*grpc.ClientConn, error) {
	var target string
	if unix != "" {
		if _, err := os.Stat(unix); err == nil {
			target = "unix://" + unix
		} else {
			target = addr
		}
	} else {
		target = addr
	}

	return grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}
