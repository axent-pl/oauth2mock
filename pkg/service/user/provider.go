package userservice

import (
	"encoding/json"
	"errors"
	"fmt"
)

// UserServiceProvider interface for construction of UserServicer from configuration
type UserServiceProvider interface {
	Init() (UserServicer, error)
}

// map of registered UserServicer sources
var userServiceProviderRegistry = make(map[string]func() UserServiceProvider)

// register provider constructor
func RegisterUserServiceProvider(name string, constructor func() UserServiceProvider) {
	userServiceProviderRegistry[name] = constructor
}

// return provider based on the configuration key
func FromJSONRawMessage(providerConfig map[string]json.RawMessage) (UserServiceProvider, error) {
	for name, rawProvider := range providerConfig {
		constructor, ok := userServiceProviderRegistry[name]
		if !ok {
			return nil, fmt.Errorf("unsupported user service provider type: %s", name)
		}
		instance := constructor()
		if err := json.Unmarshal(rawProvider, instance); err != nil {
			return nil, fmt.Errorf("failed to unmarshal %s provider: %w", name, err)
		}
		return instance, nil
	}
	return nil, errors.New("no provider")
}
