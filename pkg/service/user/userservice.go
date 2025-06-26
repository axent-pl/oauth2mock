package userservice

import (
	"encoding/json"
	"fmt"
	"os"
)

func NewUserService(jsonFilepath string) (UserServicer, error) {
	type jsonConfigStruct struct {
		Config UserServiceConfig `json:"users"`
	}
	f := jsonConfigStruct{}

	data, err := os.ReadFile(jsonFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read user service config file: %w", err)
	}

	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse user service config file: %w", err)
	}

	userService, err := f.Config.Provider.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize user service: %w", err)
	}

	return userService, nil
}
