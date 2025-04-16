package cmd

import (
	"context"
	"sort"

	"github.com/spf13/cobra"

	"github.com/ApostolDmitry/vpner/internal/common/table"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

var interfaceCmd = &cobra.Command{
	Use:   "interface",
	Short: "Work with VPN interfaces",
}

func init() {
	interfaceCmd.AddCommand(interfaceListCmd())
	interfaceCmd.AddCommand(interfaceScanCmd())
	interfaceCmd.AddCommand(interfaceAddCmd())
	interfaceCmd.AddCommand(interfaceDelCmd())
}

func interfaceListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List tracked interfaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.InterfaceList(ctx, &grpcpb.Empty{})
				if err != nil {
					return err
				}
				table := table.Table{Headers: []string{"ID", "Type", "Description", "Status"}}
				for _, iface := range resp.Interfaces {
					table.Rows = append(table.Rows, []string{
						iface.Id, iface.Type, iface.Description, iface.Status.String(),
					})
				}
				printTable(table)
				return nil
			})
		},
	}
}

func interfaceScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Scan router interfaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.InterfaceScan(ctx, &grpcpb.Empty{})
				if err != nil {
					return err
				}
				table := table.Table{Headers: []string{"ID", "Type", "Description", "Status", "Tracked"}}
				sort.Slice(resp.Interfaces, func(i, j int) bool {
					return resp.Interfaces[i].Id < resp.Interfaces[j].Id
				})
				for _, iface := range resp.Interfaces {
					tracked := "no"
					if iface.Added {
						tracked = "yes"
					}
					table.Rows = append(table.Rows, []string{
						iface.Id, iface.Type, iface.Description, iface.Status.String(), tracked,
					})
				}
				printTable(table)
				return nil
			})
		},
	}
}

func interfaceAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <id>",
		Short: "Add interface to vpner",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.InterfaceAdd(ctx, &grpcpb.InterfaceActionRequest{Id: id})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
}

func interfaceDelCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "del <id>",
		Short: "Delete interface from vpner",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.InterfaceDel(ctx, &grpcpb.InterfaceActionRequest{Id: id})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
}
