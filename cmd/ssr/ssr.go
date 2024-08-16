package ssr

import (
	"github.com/spf13/cobra"
)

var ssrCmd = &cobra.Command{
	Use:   "ssr",
	Short: "Управление ShadowSocks соединением.",
}

func Init() {
	ssrCmd.AddCommand(ssrAdd())
	ssrCmd.AddCommand(ssrDel())
	ssrCmd.AddCommand(ssrDown())
	ssrCmd.AddCommand(ssrList())
	ssrCmd.AddCommand(ssrUp())
}

func GetSrrCommand() *cobra.Command {
	return ssrCmd
}
