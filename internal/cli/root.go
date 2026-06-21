package cli

import (
	"os"

	"github.com/ApostolDmitry/vpner/internal/buildinfo"
	"github.com/ApostolDmitry/vpner/internal/rpcclient"
	"github.com/spf13/cobra"
)

var (
	cfgPath      string
	addr         string
	unixPath     string
	password     string
	timeout      string
	defaultChain string

	rt                   *rpcclient.Runtime
	resolvedDefaultChain string

	rootCmd = &cobra.Command{
		Use:     "vpnerctl",
		Short:   "CLI for managing vpnerd",
		Version: buildinfo.String(),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if rt != nil {
				return nil
			}
			opts, err := rpcclient.ResolveOptions(rpcclient.Options{
				ConfigPath:   cfgPath,
				Addr:         addr,
				Unix:         unixPath,
				Password:     password,
				Timeout:      timeout,
				DefaultChain: defaultChain,
			})
			if err != nil {
				return err
			}
			rpcTimeout = opts.Timeout
			resolvedDefaultChain = opts.DefaultChain
			rt, err = rpcclient.NewRuntime(opts)
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
	rootCmd.PersistentFlags().StringVar(&defaultChain, "default-chain", "", "default chain for commands that require --chain")

	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(doctorCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(dnsCmd)
	rootCmd.AddCommand(unblockCmd)
	rootCmd.AddCommand(interfaceCmd)
	rootCmd.AddCommand(xrayCmd)
}
