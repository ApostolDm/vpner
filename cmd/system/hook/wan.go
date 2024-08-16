package hook

import (
	"github.com/spf13/cobra"
)

func hookWan() *cobra.Command {
	cmd := &cobra.Command{
		Use: "wan",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}
	return cmd
}
