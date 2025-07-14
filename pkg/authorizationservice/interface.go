package authorizationservice

import (
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type AuthorizationRequester interface {
	GetResponseType() string
	GetRedirectURI() string
	GetScopes() []string
	GetState() string
	GetNonce() string

	GetClient() clientservice.Entity
	GetUser() userservice.Entity
}

type AuthorizationServicer interface {
	Validate(AuthorizationRequester) error
	Store(AuthorizationRequester) (string, error)
	Get(string) (AuthorizationRequester, error)
}
