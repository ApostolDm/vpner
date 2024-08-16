package unblock

import (
	"fmt"

	manager_interface "github.com/ApostolDmitry/vpner/internal/interface"
	manager_network "github.com/ApostolDmitry/vpner/internal/network"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/spf13/cobra"
)

func unblockAdd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add [domain/pattern]",
		Short: "Добавить шаблон (Например: *google.com, google.com*, *google.com*)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			pattern := args[0]

			if err := utils.ValidatePattern(pattern); err != nil {
				fmt.Println("Ошибка:", err)
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

			// Загружаем все правила всех VPN-типов
			allRules, err := unblockManager.GetAllRules()
			if err != nil {
				fmt.Println("Ошибка чтения правил:", err)
				return
			}

			for typ, setPtr := range allRules.RuleMap() {
				if setPtr == nil {
					continue
				}
				for chain, rules := range *setPtr {
					for _, existing := range rules {
						if utils.PatternsOverlap(existing, pattern) {
							fmt.Printf("Ошибка: новое правило '%s' пересекается с уже существующим правилом '%s' в [%s/%s]\n", pattern, existing, typ, chain)
							return
						}
					}
				}
			}

			if err := unblockManager.AddRule(vpnType, chainName, pattern); err != nil {
				fmt.Println("Ошибка добавления правила:", err)
				return
			}

			fmt.Println("Правило успешно добавлено.")
		},
	}

	cmd.Flags().StringP("chainName", "c", "", "Имя интерфейса, к которому применяются правила. Посмотреть можно: vpner vpn list")
	return cmd
}
