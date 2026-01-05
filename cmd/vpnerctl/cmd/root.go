package cmd

import (
	"os"

	"github.com/ApostolDmitry/vpner/cmd/vpnerctl/internal/client"
	"github.com/spf13/cobra"
)

var (
	cfgPath  string
	addr     string
	unixPath string
	password string
	timeout  string

	rt *client.Runtime

	rootCmd = &cobra.Command{
		Use:   "vpnerctl",
		Short: "CLI for managing vpnerd",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if rt != nil {
				return nil
			}
			opts, err := client.ResolveOptions(client.Options{
				ConfigPath: cfgPath,
				Addr:       addr,
				Unix:       unixPath,
				Password:   password,
				Timeout:    timeout,
			})
			if err != nil {
				return err
			}
			rpcTimeout = opts.Timeout
			rt, err = client.NewRuntime(opts)
			return err
		},
	}
)

func Execute() {
	defer func() {
		if rt != nil {
			rt.Close()
		}
	}()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", "", "path to CLI config (default ~/.vpner.cnf)")
	rootCmd.PersistentFlags().StringVar(&addr, "addr", "", "vpnerd TCP address")
	rootCmd.PersistentFlags().StringVar(&unixPath, "unix", "", "vpnerd unix socket")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "password for vpnerd")
	rootCmd.PersistentFlags().StringVar(&timeout, "timeout", "", "RPC timeout (e.g. 30s or 10 for seconds)")

	rootCmd.AddCommand(dnsCmd)
	rootCmd.AddCommand(unblockCmd)
	rootCmd.AddCommand(interfaceCmd)
	rootCmd.AddCommand(xrayCmd)
}
