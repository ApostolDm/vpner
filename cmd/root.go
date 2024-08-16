package cmd

import (
	"os"

	"github.com/ApostolDmitry/vpner/cmd/ssr"
	"github.com/ApostolDmitry/vpner/cmd/system"
	"github.com/ApostolDmitry/vpner/cmd/unblock"
	"github.com/ApostolDmitry/vpner/cmd/vpn"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "vpner",
	Short: "Утилита для работы с разными vpn сетями. Включая SS и OpenVPN",
}

var completionCmd = &cobra.Command{
	Use:    "completion",
	Short:  "Генерация скриптов автодополнения",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		RootCmd.GenBashCompletion(os.Stdout)
	},
}
func init() {
	RootCmd.AddCommand(completionCmd)
	system.Init()
	vpn.Init()
	unblock.Init()
	ssr.Init()
	RootCmd.AddCommand(system.GetSystemCommand())
	RootCmd.AddCommand(vpn.GetVPNCommand())
	RootCmd.AddCommand(unblock.GetUnblockCommand())
	RootCmd.AddCommand(ssr.GetSrrCommand())
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(0)
	}
}
