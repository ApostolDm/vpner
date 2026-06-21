package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ApostolDmitry/vpner/internal/conf"
)

func noDial(*cobra.Command, []string) error { return nil }

const defaultConfigPath = "/opt/etc/vpner/vpner.yaml"

func configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Config helpers"}
	cmd.AddCommand(configCheckCmd())
	return cmd
}

func configCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "check [path]",
		Short:             "Validate the daemon config file (strict; catches unknown keys)",
		Args:              cobra.MaximumNArgs(1),
		PersistentPreRunE: noDial,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := defaultConfigPath
			if len(args) == 1 {
				path = args[0]
			}
			if err := conf.LoadStrict(path); err != nil {
				return err
			}
			fmt.Printf("OK: %s is valid\n", path)
			return nil
		},
	}
}
