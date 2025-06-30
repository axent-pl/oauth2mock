package userservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

type UserServiceFactory func(json.RawMessage) (UserServicer, error)

var (
	userServiceFactoryRegistryMU sync.RWMutex
	userServiceFactoryRegistry   = map[string]UserServiceFactory{}
)

func Register(name string, f UserServiceFactory) {
	userServiceFactoryRegistryMU.Lock()
	defer userServiceFactoryRegistryMU.Unlock()
	userServiceFactoryRegistry[name] = f
}

type Config struct {
	UsersConfig json.RawMessage `json:"users"`
}

func NewFromConfig(rawConfig []byte) (UserServicer, error) {
	config := Config{}
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, errors.New("failed to unmarshal config")
	}

	var usersMap map[string]json.RawMessage
	if err := json.Unmarshal(config.UsersConfig, &usersMap); err != nil {
		return nil, errors.New("failed to parse users config")
	}

	providerRaw, ok := usersMap["provider"]
	if !ok {
		return nil, errors.New("missing users.provider")
	}

	var provider string
	if err := json.Unmarshal(providerRaw, &provider); err != nil {
		return nil, errors.New("invalid users.provider")
	}

	userServiceFactoryRegistryMU.RLock()
	factory, ok := userServiceFactoryRegistry[provider]
	userServiceFactoryRegistryMU.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown user service provider: %s", provider)
	}

	return factory(config.UsersConfig)
}
