package cli

import (
	"context"

	"github.com/spf13/cobra"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

func syncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Re-populate ipset entries for all unblock rules",
		Long: "Re-adds static IP/subnet rules and re-resolves concrete domain rules, " +
			"restoring ipset entries that may have expired or been flushed from the kernel.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.SyncRules(ctx, &grpcpb.Empty{})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
}
