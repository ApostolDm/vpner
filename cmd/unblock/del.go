package unblock

import (
	"fmt"
	"strings"

	manager_interface "github.com/ApostolDmitry/vpner/internal/interface"
	manager_network "github.com/ApostolDmitry/vpner/internal/network"
	"github.com/spf13/cobra"
)

func unblockDel() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "del [domain/pattern]",
		Short: "Удаляет шаблон из unblock list (например: *google*, или просто google.com)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			pattern := args[0]

			if strings.ContainsAny(pattern, "?[]") {
				fmt.Println("Ошибка: недопустимые символы в шаблоне. Разрешён только '*'")
				return
			}

			chainName, _ := cmd.Flags().GetString("chainName")
			if chainName == "" {
				fmt.Println("Ошибка: флаг --chainName (-c) обязателен")
				return
			}

			ifManager := manager_interface.NewInterfaceManager("")
			vpnType, exists := ifManager.PrintInterfaceTypeByName(chainName)
			if !exists {
				fmt.Println("Ошибка: такого `chainName` не существует.")
				return
			}

			unblockManager := manager_network.NewUnblockManager("")
			rules, err := unblockManager.GetRules(vpnType, chainName)
			if err != nil {
				fmt.Println("Ошибка чтения правил:", err)
				return
			}

			ruleSet := make(map[string]struct{}, len(rules))
			for _, r := range rules {
				ruleSet[r] = struct{}{}
			}

			if _, exists := ruleSet[pattern]; !exists {
				fmt.Println("Ошибка: такого правила нет в списке.")
				return
			}

			if err := unblockManager.DelRule(vpnType, chainName, pattern); err != nil {
				fmt.Println("Ошибка удаления правила:", err)
				return
			}

			fmt.Println("Правило успешно удалено.")
		},
	}

	cmd.Flags().StringP("chainName", "c", "", "Имя интерфейса, к которому применяются правила. Посмотреть можно: vpner vpn list")
	return cmd
}
