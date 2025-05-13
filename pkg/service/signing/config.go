package signing

import (
	"encoding/json"
	"fmt"
)

type SigningServiceKeyConfig struct {
	Source SigningKeySourcer `json:"source"`
	Type   KeyType           `json:"type"`
	Method SigningMethod     `json:"method"`
	Active bool              `json:"active"`
}

func (cfg *SigningServiceKeyConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Source map[string]json.RawMessage `json:"source"`
		Type   KeyType                    `json:"type"`
		Method SigningMethod              `json:"method"`
		Active bool                       `json:"active"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	cfg.Type = raw.Type
	cfg.Method = raw.Method
	cfg.Active = raw.Active

	for name, rawSource := range raw.Source {
		constructor, ok := signingKeySourceRegistry[name]
		if !ok {
			return fmt.Errorf("unsupported key source type: %s", name)
		}
		instance := constructor()
		if err := json.Unmarshal(rawSource, instance); err != nil {
			return fmt.Errorf("failed to unmarshal %s source: %w", name, err)
		}
		cfg.Source = instance
	}

	return nil
}
