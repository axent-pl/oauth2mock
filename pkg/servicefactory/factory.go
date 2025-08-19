package servicefactory

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

type ConstructorFunction[S any] func(globalConfigJSON json.RawMessage, serviceConfigJSON json.RawMessage) (S, error)
type ConfigExtractFunction func(globalConfigJSON json.RawMessage) (string, json.RawMessage, error)

func GenericConfigExtractFunction(providerPath string, serviceConfigPath string) ConfigExtractFunction {
	return func(globalConfigJSON json.RawMessage) (string, json.RawMessage, error) {
		providerRaw, err := extractRaw(globalConfigJSON, providerPath)
		if err != nil {
			return "", nil, fmt.Errorf("could not extract provider from `%s` path: %v", providerPath, err)
		}
		var provider string
		if err := json.Unmarshal(providerRaw, &provider); err != nil {
			return "", nil, fmt.Errorf("invalid provider value: %v", err)
		}

		serviceConfig, err := extractRaw(globalConfigJSON, serviceConfigPath)
		if err != nil {
			return "", nil, fmt.Errorf("could not extract service config from `%s` path: %v", serviceConfigPath, err)
		}

		return provider, serviceConfig, err
	}
}

type Registry[S any] struct {
	constructorMapMU sync.RWMutex
	constructorMap   map[string]ConstructorFunction[S]
	configExtractor  ConfigExtractFunction
}

func (r *Registry[S]) Register(name string, f ConstructorFunction[S], c ConfigExtractFunction) {
	slog.Info(fmt.Sprintf("Registering provider %s", name))
	r.constructorMapMU.Lock()
	defer r.constructorMapMU.Unlock()
	r.constructorMap[name] = f
	r.configExtractor = c
}

func (r *Registry[S]) Factory(globalConfigJSONBytes []byte) (S, error) {
	var emptyService S
	globalConfigJSON := json.RawMessage(globalConfigJSONBytes)
	r.constructorMapMU.RLock()
	defer r.constructorMapMU.RUnlock()

	provider, serviceConfigJSON, err := r.configExtractor(globalConfigJSON)
	if err != nil {
		return emptyService, fmt.Errorf("could not extract provider and service config from JSON: %v", err)
	}

	factory, ok := r.constructorMap[provider]
	if !ok {
		return emptyService, fmt.Errorf("unknown service provider: %s", provider)
	}

	service, err := factory(globalConfigJSON, serviceConfigJSON)
	if err != nil {
		return emptyService, fmt.Errorf("could not initialize service: %v", err)
	}

	return service, nil
}

func NewServiceFactoryRegistry[S any]() *Registry[S] {
	r := &Registry[S]{
		constructorMap: make(map[string]ConstructorFunction[S]),
	}
	return r
}

func extractRaw(data json.RawMessage, path string) (json.RawMessage, error) {
	if len(path) == 0 {
		return data, nil
	}

	keys := strings.Split(path, ".")
	var current json.RawMessage = data

	for _, key := range keys {
		// Unmarshal into a generic map
		var m map[string]json.RawMessage
		if err := json.Unmarshal(current, &m); err != nil {
			return nil, fmt.Errorf("failed to unmarshal at %q: %w", key, err)
		}

		// Check existence
		val, ok := m[key]
		if !ok {
			return nil, errors.New("path not found: " + key)
		}

		current = val
	}

	return current, nil
}
