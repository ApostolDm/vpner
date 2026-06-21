package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
	"github.com/ApostolDmitry/vpner/internal/tablefmt"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show a daemon-wide status overview",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.Status(ctx, &grpcpb.Empty{})
				if err != nil {
					return err
				}
				printStatus(resp)
				return nil
			})
		},
	}
}

func printStatus(s *grpcpb.StatusResponse) {
	dns := "stopped"
	if s.DnsRunning {
		dns = fmt.Sprintf("running :%d", s.DnsPort)
	}
	mode := "REDIRECT"
	if s.TproxyEnabled {
		mode = "TPROXY"
	}
	fmt.Printf("vpnerd %s  (up %s)\n", s.Version, humanSeconds(s.UptimeSeconds))
	fmt.Printf("DNS: %s   mode: %s   unblock rules: %d\n", dns, mode, s.UnblockRuleCount)

	if len(s.Chains) > 0 {
		tbl := tablefmt.Table{Headers: []string{"Chain", "Type", "Host", "Port", "In", "AutoRun", "State", "Restarts", "Uptime"}}
		for _, ch := range s.Chains {
			state := "down"
			if ch.Running {
				state = "up"
			}
			tbl.Rows = append(tbl.Rows, []string{
				ch.Name, ch.Type, ch.Host,
				fmt.Sprintf("%d", ch.Port), fmt.Sprintf("%d", ch.InboundPort),
				yesNo(ch.AutoRun), state,
				fmt.Sprintf("%d", ch.Restarts), humanSeconds(ch.UptimeSeconds),
			})
		}
		fmt.Println()
		printTable(tbl)
	}

	if len(s.DohServers) > 0 {
		tbl := tablefmt.Table{Headers: []string{"DoH server", "OK", "Fail", "Latency"}}
		for _, d := range s.DohServers {
			lat := "-"
			if d.LastLatencyMs > 0 {
				lat = fmt.Sprintf("%dms", d.LastLatencyMs)
			}
			tbl.Rows = append(tbl.Rows, []string{
				d.Server, fmt.Sprintf("%d", d.Successes), fmt.Sprintf("%d", d.Failures), lat,
			})
		}
		fmt.Println()
		printTable(tbl)
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func humanSeconds(sec int64) string {
	if sec <= 0 {
		return "0s"
	}
	d := time.Duration(sec) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}
