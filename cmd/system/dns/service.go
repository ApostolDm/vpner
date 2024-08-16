package dns

import (
	"log"

	"github.com/ApostolDmitry/vpner/internal/dnsserver"
	"github.com/spf13/cobra"
)

func dnsService() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "service",
		Short: "Управление сервисом DNS",
		Run: func(cmd *cobra.Command, args []string) {
			if configFile == "" {
				log.Fatal("Не указан путь к конфигурационному файлу. Используйте флаг --config для указания пути.")
			}

			manager := dnsserver.NewServerManager(configFile)
			action, _ := cmd.Flags().GetString("action")

			switch action {
			case "start":
				if err := manager.Start(); err != nil {
					log.Fatalf("Ошибка запуска сервера: %v", err)
					return
				}
				log.Println("Сервер успешно запущен")
			case "stop":
				if err := manager.Stop(); err != nil {
					log.Fatalf("Ошибка остановки сервера: %v", err)
					return
				}
				log.Println("Сервер успешно остановлен")
			case "restart":
				if err := manager.Restart(); err != nil {
					log.Fatalf("Ошибка перезапуска сервера: %v", err)
					return
				}
				log.Println("Сервер успешно перезапущен")
			case "status":
				status, err := manager.Status()
				if err != nil {
					log.Fatalf("Ошибка получения статуса сервера: %v", err)
					return
				}
				log.Println("Статус сервера:", status)
			default:
				log.Fatalf("Неизвестное действие: %s", action)
			}
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "/opt/etc/vpner/vpner.yaml", "путь к конфигурационному файлу")
	cmd.Flags().StringP("action", "a", "status", "действие для выполнения (start, stop, restart, status)")

	return cmd
}
