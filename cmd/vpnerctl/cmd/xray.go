package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ApostolDmitry/vpner/internal/common/table"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

var xrayCmd = &cobra.Command{
	Use:   "xray",
	Short: "Manage Xray chains",
}

func init() {
	xrayCmd.AddCommand(xrayListCmd())
	xrayCmd.AddCommand(xrayCreateCmd())
	xrayCmd.AddCommand(xrayDeleteCmd())
	xrayCmd.AddCommand(xrayStartStopCmd("start", grpcpb.ManageAction_START))
	xrayCmd.AddCommand(xrayStartStopCmd("stop", grpcpb.ManageAction_STOP))
	xrayCmd.AddCommand(xrayStartStopCmd("status", grpcpb.ManageAction_STATUS))
	xrayCmd.AddCommand(xrayAutorunCmd())
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
				tbl := table.Table{Headers: []string{"Chain", "Type", "Host", "Port", "AutoRun", "Status"}}
				for _, item := range resp.List {
					status := "down"
					if item.Status {
						status = "running"
					}
					auto := "no"
					if item.AutoRun {
						auto = "yes"
					}
					tbl.Rows = append(tbl.Rows, []string{
						item.ChainName,
						item.Type,
						item.Host,
						fmt.Sprintf("%d", item.Port),
						auto,
						status,
					})
				}
				printTable(tbl)
				return nil
			})
		},
	}
}

func xrayCreateCmd() *cobra.Command {
	var autorun bool
	cmd := &cobra.Command{
		Use:   "create <link>",
		Short: "Create chain from subscription link",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			link := args[0]
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.XrayCreate(ctx, &grpcpb.XrayCreateRequest{
					Link:    link,
					AutoRun: autorun,
				})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
	cmd.Flags().BoolVar(&autorun, "autorun", false, "start chain after creation")
	return cmd
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
