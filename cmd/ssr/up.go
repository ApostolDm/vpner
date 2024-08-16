package ssr

import (
	"github.com/spf13/cobra"
)

func ssrUp() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Управление ShadowSocks соединением.",
	}
	return cmd
}
