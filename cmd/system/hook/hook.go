package hook

import (
	"github.com/spf13/cobra"
)

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Обработка системных изменений роутера!",
}

func Init() {
	hookCmd.AddCommand(hookFs())
	hookCmd.AddCommand(hookIfCreated())
	hookCmd.AddCommand(hookIfDestroyed())
	hookCmd.AddCommand(hookIfLayerChanged())
	hookCmd.AddCommand(hookIfStateChanged())
	hookCmd.AddCommand(hookNetfilter())
	hookCmd.AddCommand(hookWan())
}

func GetHookCommand() *cobra.Command {
	return hookCmd
}
