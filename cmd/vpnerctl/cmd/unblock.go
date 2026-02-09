package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ApostolDmitry/vpner/internal/common/table"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

var (
	unblockCmd = &cobra.Command{
		Use:   "unblock",
		Short: "Manage unblock rules",
	}
)

func init() {
	unblockCmd.AddCommand(unblockListCmd())
	unblockCmd.AddCommand(unblockAddCmd())
	unblockCmd.AddCommand(unblockDelCmd())
	unblockCmd.AddCommand(unblockImportFileCmd())
	unblockCmd.AddCommand(unblockDeleteFileCmd())
}

func unblockListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show unblock rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.UnblockList(ctx, &grpcpb.Empty{})
				if err != nil {
					return err
				}
				table := table.Table{
					Headers: []string{"VPN Type", "Chain", "Pattern"},
				}
				for _, rule := range resp.Rules {
					for _, pattern := range rule.Rules {
						table.Rows = append(table.Rows, []string{rule.TypeName, rule.ChainName, pattern})
					}
				}
				printTable(table)
				return nil
			})
		},
	}
}

func unblockAddCmd() *cobra.Command {
	var chain string
	cmd := &cobra.Command{
		Use:   "add <pattern>",
		Short: "Add unblock pattern (domain, IP or subnet)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			chain, err = resolveChainOrPrompt(chain)
			if err != nil {
				return err
			}
			pattern := args[0]
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.UnblockAdd(ctx, &grpcpb.UnblockAddRequest{
					Domain:    pattern,
					ChainName: chain,
				})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
	cmd.Flags().StringVar(&chain, "chain", "", "chain name (VPN interface)")
	return cmd
}

func unblockDelCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "del <pattern>",
		Short: "Delete unblock pattern (domain, IP or subnet)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pattern := args[0]
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				resp, err := c.UnblockDel(ctx, &grpcpb.UnblockDelRequest{Domain: pattern})
				if err != nil {
					return err
				}
				return printGenericResponse(resp)
			})
		},
	}
}

func unblockImportFileCmd() *cobra.Command {
	var (
		chain string
		file  string
	)
	cmd := &cobra.Command{
		Use:   "import-file",
		Short: "Import unblock patterns from a file",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			chain, err = resolveChainOrPrompt(chain)
			if err != nil {
				return err
			}
			patterns, err := readPatternsFromFile(file)
			if err != nil {
				return err
			}
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				var imported int
				for _, pattern := range patterns {
					resp, err := c.UnblockAdd(ctx, &grpcpb.UnblockAddRequest{Domain: pattern, ChainName: chain})
					if err != nil {
						return fmt.Errorf("%s: %w", pattern, err)
					}
					if err := checkGenericResponse(resp); err != nil {
						return fmt.Errorf("%s: %w", pattern, err)
					}
					imported++
				}
				fmt.Printf("Imported %d patterns from %s\n", imported, file)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&chain, "chain", "", "chain name (VPN interface)")
	cmd.Flags().StringVar(&file, "file", "", "path to file with patterns")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func unblockDeleteFileCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "delete-file",
		Short: "Delete unblock patterns listed in a file",
		RunE: func(cmd *cobra.Command, args []string) error {
			patterns, err := readPatternsFromFile(file)
			if err != nil {
				return err
			}
			return withClient(func(ctx context.Context, c grpcpb.VpnerManagerClient) error {
				var removed int
				for _, pattern := range patterns {
					resp, err := c.UnblockDel(ctx, &grpcpb.UnblockDelRequest{Domain: pattern})
					if err != nil {
						return fmt.Errorf("%s: %w", pattern, err)
					}
					if err := checkGenericResponse(resp); err != nil {
						return fmt.Errorf("%s: %w", pattern, err)
					}
					removed++
				}
				fmt.Printf("Deleted %d patterns from %s\n", removed, file)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "path to file with patterns")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func readPatternsFromFile(path string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("--file is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	var result []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result = append(result, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no patterns found in %s", path)
	}
	return result, nil
}
