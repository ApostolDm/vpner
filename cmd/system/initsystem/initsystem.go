package initsystem

import (
	"github.com/ApostolDmitry/vpner/internal/initsystem"
	"github.com/spf13/cobra"
)

func InitSystem() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Первичная инцилизация конфигов",
		Run: func(cmd *cobra.Command, args []string) {
			initsystem.Init()
		},
	}
	return cmd
}
