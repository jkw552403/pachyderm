package server

import (
	"sync"

	"github.com/pachyderm/pachyderm/src/client"
	"github.com/pachyderm/pachyderm/src/client/admin"
	"github.com/pachyderm/pachyderm/src/server/pkg/log"
)

type apiServer struct {
	log.Logger
	address        string
	pachClient     *client.APIClient
	pachClientOnce sync.Once
}

func (a *apiServer) Extract(request *admin.ExtractRequest, extractServer admin.API_ExtractServer) error {
	return nil
}

func (a *apiServer) Restore(restoreServer admin.API_RestoreServer) error {
	return nil
}

func (a *apiServer) getPachClient() (*client.APIClient, error) {
	if a.pachClient == nil {
		var onceErr error
		a.pachClientOnce.Do(func() {
			a.pachClient, onceErr = client.NewFromAddress(a.address)
		})
		if onceErr != nil {
			return nil, onceErr
		}
	}
	return a.pachClient, nil
}