package clientservice

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type Entity interface {
	Id() string
	Name() string
	RedirectURIPattern() string
	AuthenticationScheme() authentication.SchemeHandler
	ValidateRedirectURI(redirectURI string) bool
}

type Service interface {
	GetClient(client_id string) (Entity, error)
	Authenticate(credentials authentication.CredentialsHandler) (Entity, error)
}
