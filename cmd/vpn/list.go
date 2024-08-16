package vpn

import (
	"fmt"

	manager_interface "github.com/ApostolDmitry/vpner/internal/interface"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func vpnList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Сканирует текущие VPN соединения для дальнейшего добавления в систему",
		RunE: func(cmd *cobra.Command, args []string) error {
			defaultManager := manager_interface.NewInterfaceManager("")
			vpnInterfaces, err := defaultManager.ReadInterfaces()
			if err != nil {
				return fmt.Errorf("ошибка при чтении YAML файла: %v", err)
			}

			if len(vpnInterfaces.Interfaces) == 0 {
				color.Yellow("Нет доступных VPN интерфейсов.")
				return nil
			}
			fmt.Println("Список VPN интерфейсов:")
			for id, iface := range vpnInterfaces.Interfaces {
				t := utils.Table{
					Rows: [][]string{
						{"ID", id},
						{"Тип", iface.Type},
						{"Описание", iface.Description},
						{"Статус", iface.State},
					},
				}
				t.Print()
			}
			return nil
		},
	}
	return cmd
}
