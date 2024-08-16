package ssr

import (
	"github.com/spf13/cobra"
)

func ssrAdd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Управление ShadowSocks соединением.",
	}
	
	return cmd
}
