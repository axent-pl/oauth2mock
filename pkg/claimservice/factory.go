package claimservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

type ClaimServiceFactory func(json.RawMessage, json.RawMessage) (ClaimServicer, error)

var (
	userServiceFactoryRegistryMU sync.RWMutex
	userServiceFactoryRegistry   = map[string]ClaimServiceFactory{}
)

func Register(name string, f ClaimServiceFactory) {
	userServiceFactoryRegistryMU.Lock()
	defer userServiceFactoryRegistryMU.Unlock()
	userServiceFactoryRegistry[name] = f
}

type Config struct {
	ClaimsConfig json.RawMessage `json:"claims"`
}

func NewFromConfig(rawConfig []byte) (ClaimServicer, error) {
	config := Config{}
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, errors.New("failed to unmarshal config")
	}

	var claimsConfig map[string]json.RawMessage
	if err := json.Unmarshal(config.ClaimsConfig, &claimsConfig); err != nil {
		return nil, errors.New("failed to parse claims config")
	}

	providerRaw, ok := claimsConfig["provider"]
	if !ok {
		return nil, errors.New("missing claims.provider")
	}

	var provider string
	if err := json.Unmarshal(providerRaw, &provider); err != nil {
		return nil, errors.New("invalid claims.provider")
	}

	userServiceFactoryRegistryMU.RLock()
	factory, ok := userServiceFactoryRegistry[provider]
	userServiceFactoryRegistryMU.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown claims service provider: %s", provider)
	}

	return factory(config.ClaimsConfig, rawConfig)
}
