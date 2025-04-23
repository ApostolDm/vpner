package cmd

import (
	"fmt"
	"os"
	"strings"

	pb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/spf13/cobra"
)

var dnsCmd = &cobra.Command{
	Use:   "dns [start|down|status|restart]",
	Short: "Управление DNS-сервером",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		actionStr := strings.ToLower(args[0])
		var action pb.ManageAction

		switch actionStr {
		case "start":
			action = pb.ManageAction_START
		case "down":
			action = pb.ManageAction_STOP
		case "status":
			action = pb.ManageAction_STATUS
		case "restart":
			action = pb.ManageAction_RESTART
		default:
			fmt.Fprintf(os.Stderr, "Неизвестное действие: %s\n", actionStr)
			os.Exit(1)
		}

		client := pb.NewVpnerManagerClient(conn)
		resp, err := client.DnsManage(ctx, &pb.ManageRequest{Act: action})
		if err != nil {
			fmt.Fprintf(os.Stderr, "gRPC ошибка: %v\n", err)
			os.Exit(1)
		}

		switch r := resp.Result.(type) {
		case *pb.GenericResponse_Success:
			fmt.Println(r.Success.Message)
		case *pb.GenericResponse_Error:
			fmt.Printf("Ошибка: %s\n", r.Error.Message)
		default:
			fmt.Println("Неизвестный ответ")
		}
	},
}
