package hook

import (
	"github.com/spf13/cobra"
)

func hookIfLayerChanged() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iflayerchanged",
		Short: "Обработка данных при изменении интерфейса",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}
	return cmd
}
