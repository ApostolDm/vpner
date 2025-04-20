package cmd

import "github.com/spf13/cobra"

var ssCmd = &cobra.Command{
	Use:   "ss",
	Short: "Работает c shadowsocks соединением. (Требует установки ss-redir)",
}
