package ssr

import (
	"github.com/spf13/cobra"
)

func ssrDown() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "down",
		Short: "Управление ShadowSocks соединением.",
	}
	return cmd
}

