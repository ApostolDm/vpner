package dns

import (
	"github.com/spf13/cobra"
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Управление DNS сервером и сервисом (Только для отладки и профилирования)",
	Long: "Тут можно принудительно управлять сервисом в dns-proxy и отладочно запустить dns-proxy cо своими значения.\n" +
		"ВНИМАНИЕ!!! ЕСЛИ НЕТ ПОНИМАНИЯ ЭТИХ ПРОЦЕССОВ НЕ ЛЕЗЬТЕ!!!",
}

func Init() {
	dnsCmd.AddCommand(dnsServer())
	dnsCmd.AddCommand(dnsService())
}

func GetDNSCommand() *cobra.Command {
	return dnsCmd
}
