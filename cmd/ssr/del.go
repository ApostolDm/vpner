package ssr

import (
	"github.com/spf13/cobra"
)

func ssrDel() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "del",
		Short: "Управление ShadowSocks соединением.",
	}
	return cmd
}
