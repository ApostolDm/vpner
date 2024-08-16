package unblock

import (
	manager_network "github.com/ApostolDmitry/vpner/internal/network"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/spf13/cobra"
)

func unblockList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Отображает текущий список разблокировок",
		Run: func(cmd *cobra.Command, args []string) {
			unblockManager := manager_network.NewUnblockManager("")
			rules, err := unblockManager.GetAllRules()
			if err != nil {
				return
			}

			table := utils.Table{
				Headers: []string{"VPN Тип", "Имя интерфейса", "Шаблон"},
			}

			addRows := func(vpnType string, ruleSet manager_network.VPNRuleSet) {
				for chain, patterns := range ruleSet {
					for _, pattern := range patterns {
						table.Rows = append(table.Rows, []string{vpnType, chain, pattern})
					}
				}
			}

			addRows("Shadowsocks", rules.Shadowsocks)
			addRows("OpenVPN", rules.OpenVPN)
			addRows("Wireguard", rules.Wireguard)
			addRows("IKE", rules.IKE)
			addRows("SSTP", rules.SSTP)
			addRows("PPPOE", rules.PPPOE)
			addRows("L2TP", rules.L2TP)
			addRows("PPTP", rules.PPTP)

			table.Print()
		},
	}
	return cmd
}
