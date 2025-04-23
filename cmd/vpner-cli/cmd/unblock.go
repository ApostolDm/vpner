package cmd

import (
	"fmt"
	"os"

	pb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/spf13/cobra"
)

var unblockCmd = &cobra.Command{
	Use:   "unblock",
	Short: "Управление правилами разблокировок",
}

var unblockListCmd = &cobra.Command{
	Use:   "list",
	Short: "Вывести правила разблокировки",
	Run: func(cmd *cobra.Command, args []string) {
		client := pb.NewVpnerManagerClient(conn)
		resp, err := client.UnblockList(ctx, &pb.Empty{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			os.Exit(1)
		}

		table := utils.Table{
			Headers: []string{"VPN Тип", "Имя интерфейса", "Шаблон"},
		}

		for _, rule := range resp.Rules {
			for _, pattern := range rule.Rules {
				table.Rows = append(table.Rows, []string{rule.TypeName, rule.ChainName, pattern})
			}
		}
		table.Print()
	},
}

func UnblockAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add [domain/pattern]",
		Short: "Добавить шаблон (Например: *google.com*, google.com*, *google.com)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			pattern := args[0]

			if err := utils.ValidatePattern(pattern); err != nil {
				fmt.Println("Ошибка:", err)
				return
			}

			chainName, _ := cmd.Flags().GetString("chainName")
			if chainName == "" {
				fmt.Println("Ошибка: флаг --chainName обязателен")
				return
			}
			client := pb.NewVpnerManagerClient(conn)
			resp, err := client.UnblockAdd(ctx, &pb.UnblockAddRequest{Domain: pattern, ChainName: chainName})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
				os.Exit(1)
				return
			}
			switch r := resp.Result.(type) {
			case *pb.GenericResponse_Success:
				fmt.Println("Успешно:", r.Success.Message)

			case *pb.GenericResponse_Error:
				fmt.Println("Ошибка:", r.Error.Message)

			default:
				fmt.Println("Неизвестный результат")
			}
		},
	}
	cmd.Flags().StringP("chainName", "c", "", "Имя интерфейса, к которому применяются правила. Посмотреть можно: vpner-cli vpn list")
	return cmd
}

func UnblockDelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "del [domain/pattern]",
		Short: "Удаляет шаблон из unblock list (Например: *google.com* или просто google.com)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			pattern := args[0]

			if err := utils.ValidatePattern(pattern); err != nil {
				fmt.Println("Ошибка:", err)
				return
			}
			client := pb.NewVpnerManagerClient(conn)
			resp, err := client.UnblockDel(ctx, &pb.UnblockDelRequest{Domain: pattern})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
				os.Exit(1)
				return
			}
			switch r := resp.Result.(type) {
			case *pb.GenericResponse_Success:
				fmt.Println("Успешно:", r.Success.Message)

			case *pb.GenericResponse_Error:
				fmt.Println("Ошибка:", r.Error.Message)

			default:
				fmt.Println("Неизвестный результат")
			}
		},
	}
	return cmd
}
