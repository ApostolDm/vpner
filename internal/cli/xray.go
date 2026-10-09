package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

var xrayCmd = &cobra.Command{
	Use:   "xray",
	Short: "Manage Xray chains",
}

func init() {
	xrayCmd.AddCommand(xrayListCmd())
	xrayCmd.AddCommand(xrayCreateCmd())
	xrayCmd.AddCommand(xrayUpdateCmd())
	xrayCmd.AddCommand(xrayDeleteCmd())
	xrayCmd.AddCommand(xrayStartStopCmd("start", grpcpb.ManageAction_START))
	xrayCmd.AddCommand(xrayStartStopCmd("stop", grpcpb.ManageAction_STOP))
	xrayCmd.AddCommand(xrayStartStopCmd("status", grpcpb.ManageAction_STATUS))
	xrayCmd.AddCommand(xrayTestCmd())
	xrayCmd.AddCommand(xrayAutorunCmd())
}

func xrayTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <chain>",
		Short: "Probe a chain (config validity, server reachability, inbound port)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.XrayTest(ctx, &grpcpb.XrayRequest{ChainName: args[0]})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
}

func xrayListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List Xray chains",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.XrayList(ctx, &grpcpb.Empty{})
				if err != nil {
					return err
				}
				var rows [][]string
				for _, item := range resp.List {
					status := "down"
					if item.Status {
						status = "running"
					}
					rows = append(rows, []string{
						item.ChainName, item.Type, item.Host,
						fmt.Sprintf("%d", item.Port), yesNo(item.AutoRun), status,
					})
				}
				printTable([]string{"Chain", "Type", "Host", "Port", "AutoRun", "Status"}, rows)
				return nil
			})
		},
	}
}

func xrayCreateCmd() *cobra.Command {
	var autorun bool
	src := linkSource{}
	cmd := &cobra.Command{
		Use:   "create [link | subscription-url]",
		Short: "Create chain(s) from a share link or a subscription URL (every node becomes a chain)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			links, err := src.resolve(args)
			if err != nil {
				return err
			}
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				if len(links) == 1 {
					resp, err := c.XrayCreate(ctx, &grpcpb.XrayCreateRequest{Link: links[0], AutoRun: autorun})
					if err != nil {
						return err
					}
					return printGenericResponse(resp)
				}
				failed := 0
				for i, link := range links {
					resp, err := c.XrayCreate(ctx, &grpcpb.XrayCreateRequest{Link: link, AutoRun: autorun})
					if err != nil {
						return err
					}
					if err := checkGenericResponse(resp); err != nil {
						failed++
						fmt.Printf("%d/%d %s: SKIPPED: %v\n", i+1, len(links), describeLink(link), err)
						continue
					}
					fmt.Printf("%d/%d %s: %s\n", i+1, len(links), describeLink(link), resp.GetSuccess().Message)
				}
				if failed == len(links) {
					return fmt.Errorf("no chain was created")
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&autorun, "autorun", false, "start chain after creation")
	addLinkSourceFlags(cmd, &src)
	return cmd
}

func xrayUpdateCmd() *cobra.Command {
	src := linkSource{}
	cmd := &cobra.Command{
		Use:   "update <chain> [link | subscription-url]",
		Short: "Update chain config from a new share link or subscription URL (keeps rules)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			chain := args[0]
			links, err := src.resolve(args[1:])
			if err != nil {
				return err
			}
			if len(links) > 1 {
				var b strings.Builder
				fmt.Fprintf(&b, "the subscription has %d nodes; pick one with --index N:\n", len(links))
				for i, link := range links {
					fmt.Fprintf(&b, "  %d: %s\n", i+1, describeLink(link))
				}
				return fmt.Errorf("%s", strings.TrimRight(b.String(), "\n"))
			}
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.XrayUpdate(ctx, &grpcpb.XrayUpdateRequest{ChainName: chain, Link: links[0]})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
	addLinkSourceFlags(cmd, &src)
	return cmd
}

func addLinkSourceFlags(cmd *cobra.Command, src *linkSource) {
	cmd.Flags().StringVar(&src.file, "file", "", "read the link(s) or subscription body from a file ('-' = stdin)")
	cmd.Flags().IntVar(&src.index, "index", 0, "pick the N-th node of a subscription (1-based)")
	cmd.Flags().BoolVar(&src.insecure, "insecure", false, "skip TLS certificate verification when fetching a subscription URL")
}

func xrayDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <chain>",
		Short: "Delete Xray chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			chain := args[0]
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.XrayDelete(ctx, &grpcpb.XrayRequest{ChainName: chain})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
}

func xrayStartStopCmd(name string, action grpcpb.ManageAction) *cobra.Command {
	return &cobra.Command{
		Use:   name + " <chain>",
		Short: fmt.Sprintf("%s Xray chain", name),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			chain := args[0]
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.XrayManage(ctx, &grpcpb.XrayManageRequest{
					ChainName: chain,
					Act:       action,
				})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
}

func xrayAutorunCmd() *cobra.Command {
	var enable, disable bool
	cmd := &cobra.Command{
		Use:   "autorun <chain>",
		Short: "Toggle autorun for an Xray chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			chain := args[0]
			if enable && disable {
				return fmt.Errorf("--enable and --disable are mutually exclusive")
			}
			if !enable && !disable {
				return fmt.Errorf("specify either --enable or --disable")
			}
			auto := enable
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.XraySetAutorun(ctx, &grpcpb.XrayAutoRunRequest{
					ChainName: chain,
					AutoRun:   auto,
				})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
	cmd.Flags().BoolVar(&enable, "enable", false, "enable autorun")
	cmd.Flags().BoolVar(&disable, "disable", false, "disable autorun")
	return cmd
}
