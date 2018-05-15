package pachyderm

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	pclient "github.com/pachyderm/pachyderm/src/client"
	"github.com/pachyderm/pachyderm/src/client/auth"
)

// Revoke revokes the caller's credentials (by sending a request to Pachyderm).
// Unlike other handlers, it doesn't get assigned to a path; instead it's
// placed in Backend.Revoke in backend.go
func (b *backend) Revoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (resp *logical.Response, retErr error) {
	b.Logger().Debug(fmt.Sprintf("(%s) %s received at %s", req.ID, req.Operation, req.Path))
	defer func() {
		b.Logger().Debug(fmt.Sprintf("(%s) %s finished at %s with result (success=%t)", req.ID, req.Operation, req.Path, retErr == nil && !resp.IsError()))
	}()

	tokenIface, ok := req.Secret.InternalData["user_token"]
	if !ok {
		return "", errMissingField(key)
	}
	userToken, ok := getStringField(data, "user_token")
	if !ok {
		return "", logical.ErrorResponse(fmt.Sprintf("invalid type for param '%s' (expected string but got %T)", key, valueIface))
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if len(config.AdminToken) == 0 {
		return nil, errors.New("plugin is missing admin token")
	}
	if len(config.PachdAddress) == 0 {
		return nil, errors.New("plugin is missing pachd address")
	}

	err = revokeUserCredentials(ctx, config.PachdAddress, userToken, config.AdminToken)
	if err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

// revokeUserCredentials revokes the Pachyderm authentication token 'userToken'
// using the vault plugin's Admin credentials.
func revokeUserCredentials(ctx context.Context, pachdAddress string, userToken string, adminToken string) error {
	// Setup a single use client w the given admin token / address
	client, err := pclient.NewFromAddress(pachdAddress)
	if err != nil {
		return err
	}
	client = client.WithCtx(ctx)
	client.SetAuthToken(adminToken)
	_, err = client.AuthAPIClient.RevokeAuthToken(client.Ctx(), &auth.RevokeAuthTokenRequest{
		Token: userToken,
	})
	return err
}
