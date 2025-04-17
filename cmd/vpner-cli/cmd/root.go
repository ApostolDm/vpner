package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	configPath string
	grpcAddr   string
	unixPath   string
	password   string

	rootCmd = &cobra.Command{
		Use:   "vpner-cli",
		Short: "CLI для управления vpnerd",
	}
)

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Путь к конфигурационному файлу (по умолчанию ~/.vpner.cnf)")
	rootCmd.PersistentFlags().StringVar(&grpcAddr, "addr", "", "TCP адрес gRPC-сервера")
	rootCmd.PersistentFlags().StringVar(&unixPath, "unix", "", "Путь к Unix-сокету")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "Пароль для авторизации")

	rootCmd.AddCommand(dnsCmd)
}

func dialGRPC(addr, unix string) (*grpc.ClientConn, error) {
	var target string

	if unix != "" {
		if _, err := os.Stat(unix); err == nil {
			target = "unix://" + unix
			fmt.Printf("📡 Unix-сокет: %s\n", unix)
		} else {
			fmt.Printf("⚠ Unix сокет не найден: %s, переключаюсь на TCP\n", unix)
			target = addr
		}
	} else {
		target = addr
	}

	return grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
}
