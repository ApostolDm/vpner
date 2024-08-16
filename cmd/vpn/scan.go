package vpn

import (
	"log"

	"github.com/ApostolDmitry/vpner/internal/vpn"
	"github.com/spf13/cobra"
)

func vpnScan() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Сканирует текущие VPN соединения для дальнейшего перенаправления трафика",
		Run: func(cmd *cobra.Command, args []string) {
			err := vpn.ScanInterfaces()
			if err != nil {
				log.Fatalf("Ошибка при сканировании VPN интерфейсов: %v", err)
			}
		},
	}
	return cmd
}
