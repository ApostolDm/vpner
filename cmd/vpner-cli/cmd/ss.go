package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	pb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/spf13/cobra"
)

var ssCmd = &cobra.Command{
	Use:   "ss",
	Short: "Работает c shadowsocks соединением. (Требует установки ss-redir)",
}

func ssNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Парсит Shadowsocks (включая 2022) ссылку вида ss://",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			raw := strings.TrimPrefix(args[0], "ss://")

			if idx := strings.IndexAny(raw, "?#"); idx != -1 {
				raw = raw[:idx]
			}

			parts := strings.SplitN(raw, "@", 2)
			if len(parts) != 2 {
				fmt.Println("Неверный формат: ожидалось base64(method:password)@host:port")
				return
			}

			decoded, err := base64.StdEncoding.DecodeString(parts[0])
			if err != nil {
				decoded, err = base64.RawStdEncoding.DecodeString(parts[0])
				if err != nil {
					fmt.Println("Ошибка декодирования base64:", err)
					return
				}
			}

			authStr := string(decoded)
			authParts := strings.Split(authStr, ":")
			if len(authParts) < 2 {
				fmt.Println("Неверный формат: ожидалось method:password")
				return
			}
			mode := cmd.Flags().Lookup("mode").Value.String()
			if mode != "tcp" && mode != "udp" && mode != "tcp_and_udp" {
				fmt.Println("Неверный режим. Доступные режимы: tcp, udp, tcp_and_udp")
				return
			}
			method := authParts[0]
			password := strings.Join(authParts[1:], ":")
			hostPort := strings.Split(parts[1], ":")
			if len(hostPort) != 2 {
				fmt.Println("Неверный формат: ожидалось host:port")
				return
			}
			host := hostPort[0]
			port, err := strconv.Atoi(hostPort[1])
			if err != nil {
				fmt.Println("Ошибка преобразования порта:", err)
				return
			}
			client := pb.NewVpnerManagerClient(conn)
			resp, err := client.SSCreate(ctx, &pb.SSInfo{
				Method:   method,
				Password: password,
				Host:     host,
				Port:     int32(port),
				AutoRun:  cmd.Flags().Lookup("autoRun").Changed,
				Mode:     mode,
			})
			if err != nil {
				fmt.Println("Ошибка gRPC:", err)
				return
			}
			switch r := resp.Result.(type) {
			case *pb.GenericResponse_Success:
				fmt.Println("Успешно:", r.Success.Message)
			case *pb.GenericResponse_Error:
				fmt.Println("Ошибка:", r.Error.Message)
			default:
				fmt.Println("Неизвестный ответ")
			}

			fmt.Println("Успешно распознано:")
			fmt.Printf("  Метод:   %s\n", method)
			fmt.Printf("  Пароль:  %s\n", password)
			fmt.Printf("  Хост:  %s\n", host)
			fmt.Printf("  Порт:    %d\n", port)
			fmt.Printf("  Режим:   %s\n", mode)
			fmt.Printf("  АвтоЗапуск: %t\n", cmd.Flags().Lookup("autoRun").Changed)
		},
	}
	cmd.Flags().BoolP("autoRun", "a", false, "Автоматически запускать при старте vpner")
	cmd.Flags().StringP("mode", "m", "tcp_and_udp", "Режим работы (tcp или udp или tcp_and_udp)")
	return cmd
}

func ssListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Список всех ss соединений",
		Run: func(cmd *cobra.Command, args []string) {
			client := pb.NewVpnerManagerClient(conn)
			resp, err := client.SSList(ctx, &pb.Empty{})
			if err != nil {
				fmt.Println("Ошибка gRPC:", err)
				return
			}
			for _, ss := range resp.List {
				fmt.Printf("ID: %s, Метод: %s, Пароль: %s, Хост: %s, Порт: %d, АвтоЗапуск: %t\n",
					ss.ChainName, ss.Ss.Method, ss.Ss.Password, ss.Ss.Host, ss.Ss.Port, ss.Ss.AutoRun)
			}
			if len(resp.List) == 0 {
				fmt.Println("Нет доступных ss соединений.")
			}
		},
	}
	return cmd
}
func ssDelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "del [chainName]",
		Short: "Удаляет ss соединение",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			client := pb.NewVpnerManagerClient(conn)
			resp, err := client.SSDelete(ctx, &pb.SSDeleteRequest{ChainName: args[0]})
			if err != nil {
				fmt.Println("Ошибка gRPC:", err)
				return
			}
			switch r := resp.Result.(type) {
			case *pb.GenericResponse_Success:
				fmt.Println("Успешно:", r.Success.Message)
			case *pb.GenericResponse_Error:
				fmt.Println("Ошибка:", r.Error.Message)
			default:
				fmt.Println("Неизвестный ответ")
			}
		},
	}
	return cmd
}
func ssManageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manage [start|stop|status|restart] [chainName]",
		Short: "Управляет ss соединением",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			actionStr := strings.ToLower(args[0])
			var action pb.ManageAction
			switch actionStr {
			case "start":
				action = pb.ManageAction_START
			case "stop":
				action = pb.ManageAction_STOP
			case "status":
				action = pb.ManageAction_STATUS
			case "restart":
				action = pb.ManageAction_RESTART
			default:
				fmt.Fprintf(os.Stderr, "Неизвестное действие: %s\n", actionStr)
				return
			}
			client := pb.NewVpnerManagerClient(conn)
			resp, err := client.SSManage(ctx, &pb.SSManageRequest{
				Act:       action,
				ChainName: args[1],
			})
			if err != nil {
				fmt.Println("Ошибка gRPC:", err)
				return
			}
			switch r := resp.Result.(type) {
			case *pb.GenericResponse_Success:
				fmt.Println("Успешно:", r.Success.Message)
			case *pb.GenericResponse_Error:
				fmt.Println("Ошибка:", r.Error.Message)
			default:
				fmt.Println("Неизвестный ответ")
			}
		},
	}
	return cmd
}
