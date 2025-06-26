package userservice

import (
	"encoding/json"
)

type UserServiceConfig struct {
	Provider UserServiceProvider `json:"provider"`
}

func (cfg *UserServiceConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Provider map[string]json.RawMessage `json:"provider"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	provider, err := FromJSONRawMessage(raw.Provider)
	if err != nil {
		return err
	}
	cfg.Provider = provider

	return nil
}
