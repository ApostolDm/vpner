package ssr

import (
	"github.com/spf13/cobra"
)

func ssrList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Управление ShadowSocks соединением.",
	}
	return cmd
}
