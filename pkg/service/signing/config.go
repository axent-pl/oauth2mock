package signing

import (
	"encoding/json"
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

	provider, err := FromJSONRawMessage(raw.Provider)
	if err != nil {
		return err
	}
	cfg.Provider = provider

	return nil
}
