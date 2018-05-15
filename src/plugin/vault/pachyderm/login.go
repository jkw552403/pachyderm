package pachyderm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	pclient "github.com/pachyderm/pachyderm/src/client"
	"github.com/pachyderm/pachyderm/src/client/auth"
)

func (b *backend) loginPath() *framework.Path {
	return &framework.Path{
		// Pattern uses modified version of framework.GenericNameRegex which
		// requires a single colon
		Pattern: "login/(?P<username>\\w[\\w-]*:[\\w-]*\\w)",
		Fields: map[string]*framework.FieldSchema{
			"username": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"ttl": &framework.FieldSchema{
				Type: framework.TypeString,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathAuthLogin,
		},
	}
}

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (resp *logical.Response, retErr error) {
	b.Logger().Debug(fmt.Sprintf("(%s) %s received at %s", req.ID, req.Operation, req.Path))
	defer func() {
		b.Logger().Debug(fmt.Sprintf("(%s) %s finished at %s (success=%t)", req.ID, req.Operation, req.Path, retErr == nil && !resp.IsError()))
	}()

	username, errResp := getStringField(d, "username")
	if errResp != nil {
		return errResp, nil
	}
	ttlField, errResp := getStringField(d, "ttl")
	if errResp != nil {
		return errResp, nil
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if len(config.AdminToken) == 0 {
		return nil, errors.New("plugin is missing admin_token")
	}
	if len(config.PachdAddress) == 0 {
		return nil, errors.New("plugin is missing pachd_address")
	}
	if len(config.TTL) == 0 {
		return nil, errors.New("plugin is missing ttl")
	}

	var ttl time.Duration
	if ttlField != "" {
		ttl, _, err = b.SanitizeTTLStr(ttlField, b.System().MaxLeaseTTL().String())
	} else {
		ttl, _, err = b.SanitizeTTLStr(config.TTL, b.System().MaxLeaseTTL().String())
	}
	if err != nil {
		return nil, err
	}

	userToken, err := generateUserCredentials(ctx, config.PachdAddress, config.AdminToken, username, ttl)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{
				"user_token": userToken,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       ttl,
				Renewable: true,
			},
		},
		Data: map[string]interface{}{
			"user_token":    userToken,
			"pachd_address": config.PachdAddress,
		},
	}, nil
}

// generateUserCredentials uses the vault plugin's Admin credentials to generate
// a new Pachyderm authentication token for 'username' (i.e. the user who is
// currently requesting a Pachyderm token from Vault).
func generateUserCredentials(ctx context.Context, pachdAddress string, adminToken string, username string, ttl time.Duration) (string, error) {
	// Setup a single use client w the given admin token / address
	client, err := pclient.NewFromAddress(pachdAddress)
	if err != nil {
		return "", err
	}
	client = client.WithCtx(ctx)
	client.SetAuthToken(adminToken)

	resp, err := client.AuthAPIClient.GetAuthToken(client.Ctx(), &auth.GetAuthTokenRequest{
		Subject: username,
		TTL:     int64(ttl.Seconds()),
	})
	if err != nil {
		return "", err
	}

	return resp.Token, nil
}
