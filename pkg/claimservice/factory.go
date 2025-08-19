package claimservice

import (
	"github.com/axent-pl/oauth2mock/pkg/servicefactory"
)

var (
	claimServiceFactoryRegistry *servicefactory.Registry[Service] = servicefactory.NewServiceFactoryRegistry[Service]()
)

func Register(name string, f servicefactory.ConstructorFunction[Service]) {
	claimServiceFactoryRegistry.Register(name, f, servicefactory.GenericConfigExtractFunction("claims.provider", "claims"))
}

func NewFromConfig(rawConfig []byte) (Service, error) {
	return claimServiceFactoryRegistry.Factory(rawConfig)
}
