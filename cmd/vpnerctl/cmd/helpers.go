package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/ApostolDmitry/vpner/internal/common/table"
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

const rpcTimeout = 5 * time.Second

func withClient(fn func(ctx context.Context, c grpcpb.VpnerManagerClient) error) error {
	if rt == nil {
		return fmt.Errorf("client is not initialized")
	}
	ctx, cancel := rt.Context(rpcTimeout)
	defer cancel()
	return fn(ctx, rt.Client())
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

func printTable(tbl table.Table) {
	if len(tbl.Rows) == 0 {
		fmt.Println("No data")
		return
	}
	tbl.Print()
}
