package hook

import (
	"github.com/spf13/cobra"
)

func hookIfCreated() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ifcreated",
		Short: "Обработка данных при создании интерфейса.",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}
	return cmd
}
