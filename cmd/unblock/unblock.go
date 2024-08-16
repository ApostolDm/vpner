package unblock

import (
	"github.com/spf13/cobra"
)

func Init() {
	unblockCmd.AddCommand(unblockAdd())
	unblockCmd.AddCommand(unblockDel())
	unblockCmd.AddCommand(unblockList())
}

var unblockCmd = &cobra.Command{
	Use:   "unblock",
	Short: "Тут можно добавить/посмотреть/удалить проксируеммые домены",
}

func GetUnblockCommand() *cobra.Command {
	return unblockCmd
}