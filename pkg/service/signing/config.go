package signing

import (
	"encoding/json"
	"fmt"
)

type SigningServiceKeyConfig struct {
	Provider SigningKeyProvider `json:"provider"`
	Type     KeyType            `json:"type"`
	Method   SigningMethod      `json:"method"`
	Active   bool               `json:"active"`
}

func (cfg *SigningServiceKeyConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Provider map[string]json.RawMessage `json:"provider"`
		Type     KeyType                    `json:"type"`
		Method   SigningMethod              `json:"method"`
		Active   bool                       `json:"active"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	cfg.Type = raw.Type
	cfg.Method = raw.Method
	cfg.Active = raw.Active

	for name, rawProvider := range raw.Provider {
		constructor, ok := signingKeyProviderRegistry[name]
		if !ok {
			return fmt.Errorf("unsupported key provider type: %s", name)
		}
		instance := constructor()
		if err := json.Unmarshal(rawProvider, instance); err != nil {
			return fmt.Errorf("failed to unmarshal %s provider: %w", name, err)
		}
		cfg.Provider = instance
	}

	return nil
}
