package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

type Client struct {
	Id          string
	RedirectURI string
	Credentials CredentialsHandler
}

type ClientStorer interface {
	GetClient(client_id string) (*Client, error)
	Authenticate(credentials CredentialsHandler) (*Client, error)
}

type clientSimpleStore struct {
	clients map[string]Client
}

func NewClientSimpleStore(clientsJSONFilepath string) (ClientStorer, error) {
	type jsonClientStruct struct {
		Id          string `json:"client_id"`
		Secret      string `json:"client_secret"`
		RedirectURI string `json:"redirect_uri"`
	}
	type jsonStoreStruct struct {
		Clients map[string]jsonClientStruct `json:"clients"`
	}
	f := jsonStoreStruct{}

	data, err := os.ReadFile(clientsJSONFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read clients config file: %w", err)
	}

	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse clients config file: %w", err)
	}

	clientStore := clientSimpleStore{
		clients: make(map[string]Client),
	}
	for k, v := range f.Clients {
		credentials, err := NewCredentials(WithClientIdAndSecret(v.Id, v.Secret))
		if err != nil {
			panic(fmt.Errorf("failed to parse client credentials from config file: %w", err))
		}
		clientStore.clients[k] = Client{
			Id:          v.Id,
			Credentials: credentials,
			RedirectURI: v.RedirectURI,
		}
		fmt.Println(v)
	}

	return &clientStore, nil
}

func (s *clientSimpleStore) GetClient(client_id string) (*Client, error) {
	client, ok := s.clients[client_id]
	if !ok {
		return nil, ErrInvalidClientId
	}
	return &client, nil
}

func (s *clientSimpleStore) Authenticate(credentials CredentialsHandler) (*Client, error) {
	for _, client := range s.clients {
		if credentials.Match(client.Credentials) {
			return &client, nil
		}
	}
	return nil, ErrInvalidCreds
}
