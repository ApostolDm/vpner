
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var interfaceCmd = &cobra.Command{
	Use:   "interface",
	Short: "работа с интерфейсами подключений",
}

func InterfaceListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Показать текущий список интерфейсов VPN",
		Run: func(cmd *cobra.Command, args []string) {
			client := pb.NewVpnerManagerClient(conn)
			resp, err := client.InterfaceList(ctx, &pb.Empty{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
				os.Exit(1)
			}
			for _, iface := range resp.Interfaces {
				var status string
				switch iface.Status {
				case pb.InterfaceInfo_DOWN:
					status = "down"
				case pb.InterfaceInfo_UNKNOWN:
					status = "unknown"
				case pb.InterfaceInfo_UP:
					status = "up"
				}
				table := utils.Table{
					Rows: [][]string{
						{"ID", iface.Id},
						{"Type", iface.Type},
						{"Description", iface.Description},
						{"Status", status},
					},
				}
				table.Print()
			}
		},
	}
	return cmd
}

func InterfaceScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Сканирует интерфейсы в системе и выводит доступные для добавления или удаления",
		Run: func(cmd *cobra.Command, args []string) {
			client := pb.NewVpnerManagerClient(conn)
			resp, err := client.InterfaceScan(ctx, &pb.Empty{})
			if err != nil {
				color.Red("Ошибка при сканировании интерфейсов: %v", err)
				os.Exit(1)
			}

			if len(resp.Interfaces) == 0 {
				color.Yellow("Нет доступных интерфейсов.")
				return
			}

			fmt.Println("Доступные интерфейсы:")
			for i, iface := range resp.Interfaces {
				status := fmt.Sprintf("ID: %s, Type: %s, Status: %s, Desc: %s", iface.Id, iface.Type, iface.Status, iface.Description)
				if iface.Added {
					color.Green("(%d) %s [УЖЕ ДОБАВЛЕН]", i+1, status)
				} else {
					color.Cyan("(%d) %s", i+1, status)
				}
			}

			reader := bufio.NewReader(os.Stdin)
			for {
				fmt.Printf("Введите номер интерфейса для добавления/удаления (или Enter для выхода): ")
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)

				if input == "" {
					fmt.Println("Выход.")
					return
				}

				var choice int
				_, err := fmt.Sscanf(input, "%d", &choice)
				if err != nil || choice < 1 || choice > len(resp.Interfaces) {
					color.Red("Некорректный выбор. Введите число от 1 до %d", len(resp.Interfaces))
					continue
				}

				selected := resp.Interfaces[choice-1]
				fmt.Printf("Вы выбрали интерфейс: %s (%s)\n", selected.Id, selected.Type)
				callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer callCancel()

				req := &pb.InterfaceActionRequest{Id: selected.Id}

				if !selected.Added {
					addResp, err := client.InterfaceAdd(callCtx, req)
					if err != nil {
						color.Red("Ошибка при добавлении интерфейса: %v", err)
						continue
					}
					switch r := addResp.Result.(type) {
					case *pb.GenericResponse_Success:
						color.Green("Успешно добавлено: %s", r.Success.Message)
					case *pb.GenericResponse_Error:
						color.Red("Ошибка: %s", r.Error.Message)
					default:
						color.Red("Неизвестный результат")
					}
				} else {
					delResp, err := client.InterfaceDel(callCtx, req)
					if err != nil {
						color.Red("Ошибка при удалении интерфейса: %v", err)
						continue
					}
					switch r := delResp.Result.(type) {
					case *pb.GenericResponse_Success:
						color.Green("Успешно удалено: %s", r.Success.Message)
					case *pb.GenericResponse_Error:
						color.Red("Ошибка: %s", r.Error.Message)
					default:
						color.Red("Неизвестный результат")
					}
				}
				break
			}
		},
	}
	return cmd
}
