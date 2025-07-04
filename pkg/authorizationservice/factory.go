package authorizationservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

type AuthorizationServiceFactory func(rawAuthorizationConfig json.RawMessage, rawConfig json.RawMessage) (AuthorizationServicer, error)

var (
	authorizationServiceFactoryRegistryMU sync.RWMutex
	authorizationServiceFactoryRegistry   = map[string]AuthorizationServiceFactory{}
)

func Register(name string, f AuthorizationServiceFactory) {
	authorizationServiceFactoryRegistryMU.Lock()
	defer authorizationServiceFactoryRegistryMU.Unlock()
	authorizationServiceFactoryRegistry[name] = f
}

type Config struct {
	AuthorizationConfig json.RawMessage `json:"authorization"`
}

func NewFromConfig(rawConfig []byte) (AuthorizationServicer, error) {
	slog.Info("init started", "module", "authorizationservice")
	config := Config{}
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, errors.New("failed to unmarshal config")
	}

	var authorizationsConfig map[string]json.RawMessage
	if err := json.Unmarshal(config.AuthorizationConfig, &authorizationsConfig); err != nil {
		return nil, errors.New("failed to parse authorization service config")
	}

	providerRaw, ok := authorizationsConfig["provider"]
	if !ok {
		return nil, errors.New("missing authorization.provider")
	}

	var provider string
	if err := json.Unmarshal(providerRaw, &provider); err != nil {
		return nil, errors.New("invalid authorization.provider")
	}

	slog.Info("authorization service factory registry search", "provider", provider)
	authorizationServiceFactoryRegistryMU.RLock()
	factory, ok := authorizationServiceFactoryRegistry[provider]
	authorizationServiceFactoryRegistryMU.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown authorization service provider: %s", provider)
	}

	service, err := factory(config.AuthorizationConfig, rawConfig)
	if err != nil {
		slog.Error("init failed", "module", "authorizationservice", "error", err)
	} else {
		slog.Info("init done", "module", "authorizationservice")
	}

	return service, err
}
