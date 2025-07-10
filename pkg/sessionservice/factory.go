package sessionservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

type SessionServiceFactory func(json.RawMessage) (SessionService, error)

var (
	sessionServiceFactoryRegistryMU sync.RWMutex
	sessionServiceFactoryRegistry   = map[string]SessionServiceFactory{}
)

func Register(name string, f SessionServiceFactory) {
	sessionServiceFactoryRegistryMU.Lock()
	defer sessionServiceFactoryRegistryMU.Unlock()
	sessionServiceFactoryRegistry[name] = f
}

type Config struct {
	SessionsConfig json.RawMessage `json:"session"`
}

func NewFromConfig(rawConfig []byte) (SessionService, error) {
	config := Config{}
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, errors.New("failed to unmarshal config")
	}

	var sessionsMap map[string]json.RawMessage
	if err := json.Unmarshal(config.SessionsConfig, &sessionsMap); err != nil {
		return nil, errors.New("failed to parse sessions config")
	}

	providerRaw, ok := sessionsMap["provider"]
	if !ok {
		return nil, errors.New("missing sessions.provider")
	}

	var provider string
	if err := json.Unmarshal(providerRaw, &provider); err != nil {
		return nil, errors.New("invalid sessions.provider")
	}

	sessionServiceFactoryRegistryMU.RLock()
	factory, ok := sessionServiceFactoryRegistry[provider]
	sessionServiceFactoryRegistryMU.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown session service provider: %s", provider)
	}

	return factory(config.SessionsConfig)
}
