package clientservice

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/axent-pl/oauth2mock/pkg/di"
	"github.com/axent-pl/oauth2mock/pkg/errs"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
)

type clientService struct {
	clients map[string]client
}

func NewClientService(jsonFilepath string) (ClientServicer, error) {
	type jsonStruct struct {
		Id          string `json:"client_id"`
		Secret      string `json:"client_secret"`
		RedirectURI string `json:"redirect_uri"`
	}
	type jsonStoreStruct struct {
		Clients map[string]jsonStruct `json:"clients"`
	}
	f := jsonStoreStruct{}

	data, err := os.ReadFile(jsonFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read clients config file: %w", err)
	}

	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse clients config file: %w", err)
	}

	clientStore := &clientService{
		clients: make(map[string]client),
	}
	for k, v := range f.Clients {
		credentials, err := authentication.NewScheme(authentication.WithClientIdAndSecret(v.Id, v.Secret))
		if err != nil {
			panic(fmt.Errorf("failed to parse client credentials from config file: %w", err))
		}
		clientStore.clients[k] = client{
			id:                 v.Id,
			authScheme:         credentials,
			redirectURIPattern: v.RedirectURI,
		}
	}

	di.Register(clientStore)

	return clientStore, nil
}

func (s *clientService) GetClient(client_id string) (ClientHandler, error) {
	client, ok := s.clients[client_id]
	if !ok {
		return nil, errs.ErrInvalidClientId
	}
	return &client, nil
}

func (s *clientService) Authenticate(credentials authentication.CredentialsHandler) (ClientHandler, error) {
	clientId, err := credentials.IdentityName()
	if err != nil {
		return nil, errs.ErrUserCredsInvalid
	}

	client, ok := s.clients[clientId]
	if !ok {
		return nil, errs.ErrUserCredsInvalid
	}

	authenticated := client.authScheme.Matches(credentials)
	if !authenticated {
		return nil, errs.ErrUserCredsInvalid
	}

	return &client, nil
}
