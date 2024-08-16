package hook

import (
	"github.com/ApostolDmitry/vpner/internal/initsystem"
	"github.com/spf13/cobra"
)

func hookFs() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fs",
		Short: "Обработка данных при монтировании FS",
		Run: func(cmd *cobra.Command, args []string) {
			initsystem.Init()
		},
	}
	return cmd
}
