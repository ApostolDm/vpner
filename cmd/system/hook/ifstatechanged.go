package hook

import (
	"os"

	manager_interface "github.com/ApostolDmitry/vpner/internal/interface"
	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/spf13/cobra"
)

func hookIfStateChanged() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ifstatechanged",
		Short: "Обработка данных при изменении интерфейса",
		Run: func(cmd *cobra.Command, args []string) {
			if args[0] != "hook" {
				return
			}
			id := os.Getenv("id")
			system_name := os.Getenv("system_name")
			if len(system_name) == 0 {
				return
			}
			defaultManager := manager_interface.NewInterfaceManager("") 
			if err := defaultManager.UpdateInterfaceField(id, "system_name", system_name); err != nil {
				utils.LogError(err)
			}
			up := os.Getenv("up")
			if len(up) == 0 {
				return
			}
			if err := defaultManager.UpdateInterfaceField(id, "status", up); err != nil {
				utils.LogError(err)
			}
		},
	}
	return cmd
}
