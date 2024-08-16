package hook

import (
	"github.com/spf13/cobra"
)

func hookNetfilter() *cobra.Command {
	cmd := &cobra.Command{
		Use: "netfilter",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}
	return cmd
}
