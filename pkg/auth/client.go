package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

const clientsFile = "run/users.json"

type Client struct {
	Id          string `json:"client_id"`
	Secret      string `json:"client_secret"`
	RedirectURI string `json:"redirect_uri"`
}

// ----------------------------------------------------------------------------

type ClientStorer interface {
	GetClient(client_id string) (*Client, error)
	Authenticate(credentials Credentials) (*Client, error)
}

// ----------------------------------------------------------------------------

type ClientSimpleStore struct {
	clients map[string]Client
}

func NewClientSimpleStore() *ClientSimpleStore {
	type fileStructure struct {
		Clients map[string]Client `json:"clients"`
	}
	f := fileStructure{}

	data, err := os.ReadFile(clientsFile)
	if err != nil {
		panic(fmt.Errorf("failed to read clients config file: %w", err))
	}

	if err := json.Unmarshal(data, &f); err != nil {
		panic(fmt.Errorf("failed to parse clients config file: %w", err))
	}

	clientStore := ClientSimpleStore{
		clients: make(map[string]Client),
	}
	for k, v := range f.Clients {
		clientStore.clients[k] = v
		fmt.Println(v)
	}

	return &clientStore
}

func (s *ClientSimpleStore) GetClient(client_id string) (*Client, error) {
	client, ok := s.clients[client_id]
	if !ok {
		return nil, ErrInvalidClientId
	}
	return &client, nil
}

func (s *ClientSimpleStore) Authenticate(credentials Credentials) (*Client, error) {
	for _, client := range s.clients {
		if credentials.ClientId == client.Id && credentials.ClientSecret == client.Secret {
			return &client, nil
		}
	}
	return nil, ErrInvalidCreds
}
