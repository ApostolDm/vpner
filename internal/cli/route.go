package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

var routeCmd = &cobra.Command{
	Use:   "route",
	Short: "Full tunnel: send all LAN internet traffic through one chain",
	Long: "Per-rule routing (unblock rules) keeps working for other chains; everything else " +
		"from the LAN that is not a local destination goes through the selected chain.",
}

func init() {
	routeCmd.AddCommand(routeAllCmd())
	routeCmd.AddCommand(routeSplitCmd())
	routeCmd.AddCommand(routeStatusCmd())
}

func routeAllCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "all <chain>",
		Short: "Route all LAN internet traffic through <chain> (interface id or xray chain)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setDefaultRoute(args[0])
		},
	}
}

func routeSplitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "split",
		Short: "Back to per-rule routing (disable the full tunnel)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return setDefaultRoute("")
		},
	}
}

func routeStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the current routing mode (exit code 1 when the full tunnel is set but inactive)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.Status(ctx, &grpcpb.Empty{})
				if err != nil {
					return routeError(err)
				}
				if resp.DefaultRoute == nil {
					return errors.New("vpnerd is too old for route commands; update it (vpnerctl update --apply)")
				}
				fmt.Println(formatDefaultRoute(resp.DefaultRoute))
				if d := resp.DefaultRoute; d.ChainName != "" && !d.Active {
					return errors.New("default route is inactive")
				}
				return nil
			})
		},
	}
}

func setDefaultRoute(chain string) error {
	return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
		resp, err := c.SetDefaultRoute(ctx, &grpcpb.DefaultRouteRequest{ChainName: chain})
		if err != nil {
			return routeError(err)
		}
		return printGenericResponse(resp)
	})
}

func routeError(err error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("vpnerd is too old for route commands; update it (vpnerctl update --apply)")
	}
	return err
}

func formatDefaultRoute(d *grpcpb.DefaultRouteStatus) string {
	switch {
	case d == nil:
		return "route: n/a (vpnerd is too old)"
	case d.ChainName == "":
		return "route: split (per-rule routing)"
	case d.Active:
		return fmt.Sprintf("route: all via %s (%s), active", d.ChainName, d.Type)
	default:
		return fmt.Sprintf("route: all via %s (%s), INACTIVE: %s", d.ChainName, d.Type, d.Reason)
	}
}
