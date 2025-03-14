package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

type ClientServicer interface {
	GetClient(client_id string) (ClientHandler, error)
	Authenticate(credentials AuthenticationCredentialsHandler) (ClientHandler, error)
}

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

	clientStore := clientService{
		clients: make(map[string]client),
	}
	for k, v := range f.Clients {
		credentials, err := NewAuthenticationScheme(WithClientIdAndSecret(v.Id, v.Secret))
		if err != nil {
			panic(fmt.Errorf("failed to parse client credentials from config file: %w", err))
		}
		clientStore.clients[k] = client{
			id:                 v.Id,
			authScheme:         credentials,
			redirectURIPattern: v.RedirectURI,
		}
	}

	return &clientStore, nil
}

func (s *clientService) GetClient(client_id string) (ClientHandler, error) {
	client, ok := s.clients[client_id]
	if !ok {
		return nil, ErrInvalidClientId
	}
	return &client, nil
}

func (s *clientService) Authenticate(credentials AuthenticationCredentialsHandler) (ClientHandler, error) {
	clientId, err := credentials.IdentityName()
	if err != nil {
		return nil, ErrInvalidCreds
	}

	client, ok := s.clients[clientId]
	if !ok {
		return nil, ErrInvalidCreds
	}

	authenticated := client.authScheme.IsValid(credentials)
	if !authenticated {
		return nil, ErrInvalidCreds
	}

	return &client, nil
}
