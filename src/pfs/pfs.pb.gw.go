// Code generated by protoc-gen-grpc-gateway
// source: pfs/pfs.proto
// DO NOT EDIT!

/*
Package pfs is a reverse proxy.

It translates gRPC into RESTful JSON APIs.
*/
package pfs

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gengo/grpc-gateway/runtime"
	"github.com/gengo/grpc-gateway/utilities"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var _ codes.Code
var _ io.Reader
var _ = runtime.String
var _ = json.Marshal
var _ = utilities.PascalFromSnake

var (
	filter_API_CreateRepo_0 = &utilities.DoubleArray{Encoding: map[string]int{"repo": 0, "name": 1}, Base: []int{1, 1, 1, 0}, Check: []int{0, 1, 2, 3}}
)

func request_API_CreateRepo_0(ctx context.Context, client APIClient, req *http.Request, pathParams map[string]string) (proto.Message, error) {
	var protoReq CreateRepoRequest

	var (
		val string
		ok  bool
		err error
		_   = err
	)

	val, ok = pathParams["repo.name"]
	if !ok {
		return nil, grpc.Errorf(codes.InvalidArgument, "missing parameter %s", "repo.name")
	}

	err = runtime.PopulateFieldFromPath(&protoReq, "repo.name", val)

	if err != nil {
		return nil, err
	}

	if err := runtime.PopulateQueryParameters(&protoReq, req.URL.Query(), filter_API_CreateRepo_0); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "%v", err)
	}

	return client.CreateRepo(ctx, &protoReq)
}

// RegisterAPIHandlerFromEndpoint is same as RegisterAPIHandler but
// automatically dials to "endpoint" and closes the connection when "ctx" gets done.
func RegisterAPIHandlerFromEndpoint(ctx context.Context, mux *runtime.ServeMux, endpoint string) (err error) {
	conn, err := grpc.Dial(endpoint, grpc.WithInsecure())
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if cerr := conn.Close(); cerr != nil {
				glog.Errorf("Failed to close conn to %s: %v", endpoint, cerr)
			}
			return
		}
		go func() {
			<-ctx.Done()
			if cerr := conn.Close(); cerr != nil {
				glog.Errorf("Failed to close conn to %s: %v", endpoint, cerr)
			}
		}()
	}()

	return RegisterAPIHandler(ctx, mux, conn)
}

// RegisterAPIHandler registers the http handlers for service API to "mux".
// The handlers forward requests to the grpc endpoint over "conn".
func RegisterAPIHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	client := NewAPIClient(conn)

	mux.Handle("PUT", pattern_API_CreateRepo_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		resp, err := request_API_CreateRepo_0(runtime.AnnotateContext(ctx, req), client, req, pathParams)
		if err != nil {
			runtime.HTTPError(ctx, w, err)
			return
		}

		forward_API_CreateRepo_0(ctx, w, req, resp, mux.GetForwardResponseOptions()...)

	})

	return nil
}

var (
	pattern_API_CreateRepo_0 = runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 1, 0, 4, 1, 5, 1}, []string{"repos", "repo.name"}, ""))
)

var (
	forward_API_CreateRepo_0 = runtime.ForwardResponseMessage
)
