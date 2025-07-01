package claimservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

type ClaimServiceFactory func(json.RawMessage, json.RawMessage) (ClaimServicer, error)

var (
	claimServiceFactoryRegistryMU sync.RWMutex
	claimServiceFactoryRegistry   = map[string]ClaimServiceFactory{}
)

func Register(name string, f ClaimServiceFactory) {
	claimServiceFactoryRegistryMU.Lock()
	defer claimServiceFactoryRegistryMU.Unlock()
	claimServiceFactoryRegistry[name] = f
}

type Config struct {
	ClaimsConfig json.RawMessage `json:"claims"`
}

func NewFromConfig(rawConfig []byte) (ClaimServicer, error) {
	slog.Info("init started", "module", "claimservice")
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

	slog.Info("claimservice factory registry search", "provider", provider)
	claimServiceFactoryRegistryMU.RLock()
	factory, ok := claimServiceFactoryRegistry[provider]
	claimServiceFactoryRegistryMU.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown claims service provider: %s", provider)
	}

	service, err := factory(config.ClaimsConfig, rawConfig)
	if err != nil {
		slog.Error("init failed", "module", "claimservice", "error", err)
	} else {
		slog.Info("init done", "module", "claimservice")
	}

	return service, err
}
