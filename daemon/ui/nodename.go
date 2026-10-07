package ui

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// NodeNameKey is the gRPC metadata key with the name of the node
// (Server.Name in the configuration).
//
// All daemons that connect to a unix socket have the same peer address on the
// GUI. The GUI uses this name to tell them apart.
const NodeNameKey = "opensnitch-node"

func nodeNameUnaryInterceptor(name string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, NodeNameKey, name)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func nodeNameStreamInterceptor(name string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = metadata.AppendToOutgoingContext(ctx, NodeNameKey, name)
		return streamer(ctx, desc, cc, method, opts...)
	}
}
