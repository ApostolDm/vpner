package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	pb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/metadata"
)

var dnsCmd = &cobra.Command{
	Use:   "dns [start|down|status|restart]",
	Short: "Управление DNS-сервером",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		actionStr := strings.ToLower(args[0])
		var action pb.DnsManageResponseAction

		switch actionStr {
		case "start":
			action = pb.DnsManageResponse_START
		case "down":
			action = pb.DnsManageResponse_STOP
		case "status":
			action = pb.DnsManageResponse_STATUS
		case "restart":
			action = pb.DnsManageResponse_RESTART
		default:
			fmt.Fprintf(os.Stderr, "Неизвестное действие: %s\n", actionStr)
			os.Exit(1)
		}

		cfg, _ := loadCLIConfig(configPath)

		finalAddr := grpcAddr
		finalUnix := unixPath
		finalPassword := password

		if cfg != nil {
			if finalAddr == "" && cfg.Addr != "" {
				finalAddr = cfg.Addr
			}
			if finalUnix == "" && cfg.Unix != "" {
				finalUnix = cfg.Unix
			}
			if finalPassword == "" && cfg.Password != "" {
				finalPassword = cfg.Password
			}
		}

		if finalAddr == "" && finalUnix == "" {
			finalUnix = "/tmp/vpner.sock"
			fmt.Println("⚠ fallback: используем /tmp/vpner.sock")
		}

		conn, err := dialGRPC(finalAddr, finalUnix)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка подключения: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		ctx := context.Background()
		if finalPassword != "" {
			ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
				"authorization", finalPassword,
			))
		}

		client := pb.NewVpnerManagerClient(conn)
		resp, err := client.DnsManage(ctx, &pb.DnsManageResponse{Act: action})
		if err != nil {
			fmt.Fprintf(os.Stderr, "gRPC ошибка: %v\n", err)
			os.Exit(1)
		}

		switch r := resp.Result.(type) {
		case *pb.DnsManageRequest_Success:
			fmt.Println(r.Success.Message)
		case *pb.DnsManageRequest_Error:
			fmt.Printf("⚠ Ошибка: %s\n", r.Error.Message)
		default:
			fmt.Println("Неизвестный ответ от сервера")
		}
	},
}
