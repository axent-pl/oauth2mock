package signing

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SigningKeyProvider interface for construction of SigningKeyHandler from configuration
type SigningKeyProvider interface {
	Init() (SigningKeyHandler, error)
}

// map of registered SigningKeyHandler sources
var signingKeyProviderRegistry = make(map[string]func() SigningKeyProvider)

// register provider constructor
func RegisterSigningKeyProvider(name string, constructor func() SigningKeyProvider) {
	signingKeyProviderRegistry[name] = constructor
}

// return provider based on the configuration key
func FromJSONRawMessage(providerConfig map[string]json.RawMessage) (SigningKeyProvider, error) {
	for name, rawProvider := range providerConfig {
		constructor, ok := signingKeyProviderRegistry[name]
		if !ok {
			return nil, fmt.Errorf("unsupported key provider type: %s", name)
		}
		instance := constructor()
		if err := json.Unmarshal(rawProvider, instance); err != nil {
			return nil, fmt.Errorf("failed to unmarshal %s provider: %w", name, err)
		}
		return instance, nil
	}
	return nil, errors.New("no provider")
}
