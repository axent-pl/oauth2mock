package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

type Client struct {
	Id          string
	RedirectURI string
	Credentials *Credentials
}

type ClientStorer interface {
	GetClient(client_id string) (*Client, error)
	Authenticate(credentials Credentials) (*Client, error)
}

type ClientSimpleStore struct {
	clients map[string]Client
}

func NewClientSimpleStore(clientsJSONFilepath string) *ClientSimpleStore {
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
		panic(fmt.Errorf("failed to read clients config file: %w", err))
	}

	if err := json.Unmarshal(data, &f); err != nil {
		panic(fmt.Errorf("failed to parse clients config file: %w", err))
	}

	clientStore := ClientSimpleStore{
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
		if credentials.Match(client.Credentials) {
			return &client, nil
		}
	}
	return nil, ErrInvalidCreds
}
