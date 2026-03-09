package grpcserver

import (
	grpcpb "github.com/ApostolDmitry/vpner/internal/grpc"
)

func returnIfStatus(state string) grpcpb.InterfaceInfo_State {
	switch state {
	case "up":
		return grpcpb.InterfaceInfo_UP
	case "down":
		return grpcpb.InterfaceInfo_DOWN
	default:
		return grpcpb.InterfaceInfo_UNKNOWN
	}
}

func successGeneric(msg string) *grpcpb.GenericResponse {
	return &grpcpb.GenericResponse{
		Result: &grpcpb.GenericResponse_Success{
			Success: &grpcpb.Success{Message: msg},
		},
	}
}

func errorGeneric(msg string) *grpcpb.GenericResponse {
	return &grpcpb.GenericResponse{
		Result: &grpcpb.GenericResponse_Error{
			Error: &grpcpb.Error{Message: msg},
		},
	}
}
