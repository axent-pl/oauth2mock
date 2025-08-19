package claimservice

import (
	"encoding/json"

	"github.com/axent-pl/oauth2mock/pkg/servicefactory"
)

var (
	genericClaimServiceFactoryRegistry *servicefactory.Registry[Service] = servicefactory.NewServiceFactoryRegistry[Service]()
)

func Register(name string, f servicefactory.ConstructorFunction[Service]) {
	genericClaimServiceFactoryRegistry.Register(name, f, servicefactory.GenericConfigExtractFunction("claims.provider", "claims"))
}

type Config struct {
	ClaimsConfig json.RawMessage `json:"claims"`
}

func NewFromConfig(rawConfig []byte) (Service, error) {
	return genericClaimServiceFactoryRegistry.Factory(rawConfig)
}
