package consentservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

type ConsentServiceFactory func(rawConsentConfig json.RawMessage, rawConfig json.RawMessage) (ConsentServicer, error)

var (
	consentServiceFactoryRegistryMU sync.RWMutex
	consentServiceFactoryRegistry   = map[string]ConsentServiceFactory{}
)

func Register(name string, f ConsentServiceFactory) {
	consentServiceFactoryRegistryMU.Lock()
	defer consentServiceFactoryRegistryMU.Unlock()
	consentServiceFactoryRegistry[name] = f
}

type Config struct {
	ConsentsConfig json.RawMessage `json:"consents"`
}

func NewFromConfig(rawConfig []byte) (ConsentServicer, error) {
	slog.Info("init started", "module", "consentservice")
	config := Config{}
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, errors.New("failed to unmarshal config")
	}

	var consentsConfig map[string]json.RawMessage
	if err := json.Unmarshal(config.ConsentsConfig, &consentsConfig); err != nil {
		return nil, errors.New("failed to parse consents config")
	}

	providerRaw, ok := consentsConfig["provider"]
	if !ok {
		return nil, errors.New("missing consents.provider")
	}

	var provider string
	if err := json.Unmarshal(providerRaw, &provider); err != nil {
		return nil, errors.New("invalid consents.provider")
	}

	slog.Info("consentservice factory registry search", "provider", provider)
	consentServiceFactoryRegistryMU.RLock()
	factory, ok := consentServiceFactoryRegistry[provider]
	consentServiceFactoryRegistryMU.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown consents service provider: %s", provider)
	}

	service, err := factory(config.ConsentsConfig, rawConfig)
	if err != nil {
		slog.Error("init failed", "module", "consentservice", "error", err)
	} else {
		slog.Info("init done", "module", "consentservice")
	}

	return service, err
}
