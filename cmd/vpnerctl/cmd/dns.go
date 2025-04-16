package cmd

import (
	"context"

	"github.com/spf13/cobra"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Manage embedded DNS resolver",
}

func init() {
	dnsCmd.AddCommand(newDNSManageCmd("start", grpcpb.ManageAction_START))
	dnsCmd.AddCommand(newDNSManageCmd("stop", grpcpb.ManageAction_STOP))
	dnsCmd.AddCommand(newDNSManageCmd("status", grpcpb.ManageAction_STATUS))
	dnsCmd.AddCommand(newDNSManageCmd("restart", grpcpb.ManageAction_RESTART))
}

func newDNSManageCmd(name string, action grpcpb.ManageAction) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: name + " DNS server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.DnsManage(ctx, &grpcpb.ManageRequest{Act: action})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
}
