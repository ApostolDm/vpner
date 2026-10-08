package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

var rpcTimeout = 120 * time.Second

func noDial(*cobra.Command, []string) error { return nil }

func withClient(fn func(ctx context.Context, c grpcpb.VpnerManagerClient) error) error {
	if rt == nil {
		return fmt.Errorf("client is not initialized")
	}
	ctx, cancel := rt.Context(rpcTimeout)
	defer cancel()
	return fn(ctx, rt.Client())
}

func resolveChainOrPrompt(chain string) (string, error) {
	chain = strings.TrimSpace(chain)
	if chain != "" {
		return chain, nil
	}
	if resolvedDefaultChain != "" {
		return resolvedDefaultChain, nil
	}
	if !isTerminal() {
		return "", fmt.Errorf("--chain is required")
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter chain: ")
		value, err := reader.ReadString('\n')
		if err != nil && value == "" {
			return "", fmt.Errorf("--chain is required")
		}
		value = strings.TrimSpace(value)
		if value != "" {
			return value, nil
		}
	}
}

func isTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func printGenericResponse(resp *grpcpb.GenericResponse) error {
	return handleGenericResponse(resp, false)
}

func checkGenericResponse(resp *grpcpb.GenericResponse) error {
	return handleGenericResponse(resp, true)
}

func handleGenericResponse(resp *grpcpb.GenericResponse, quiet bool) error {
	switch r := resp.Result.(type) {
	case *grpcpb.GenericResponse_Success:
		if !quiet {
			fmt.Println(r.Success.Message)
		}
	case *grpcpb.GenericResponse_Error:
		return fmt.Errorf("%s", r.Error.Message)
	default:
		return fmt.Errorf("unknown response type")
	}
	return nil
}

func printTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Println("No data")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	for _, row := range rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	w.Flush()
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
