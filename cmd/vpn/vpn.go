package vpn

import (
	"github.com/spf13/cobra"
)

var VPNCmd = &cobra.Command{
	Use:   "vpn",
	Short: "Тут проивзодиться добавление vpn для дальнешего proxy",
}

func Init() {
	VPNCmd.AddCommand(vpnScan())
	VPNCmd.AddCommand(vpnList())
}

func GetVPNCommand() *cobra.Command {
	return VPNCmd
}