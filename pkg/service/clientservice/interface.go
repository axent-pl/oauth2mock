package clientservice

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type ClientHandler interface {
	Id() string
	Name() string
	RedirectURIPattern() string
	AuthenticationScheme() authentication.SchemeHandler
	ValidateRedirectURI(redirectURI string) bool
}

type ClientServicer interface {
	GetClient(client_id string) (ClientHandler, error)
	Authenticate(credentials authentication.CredentialsHandler) (ClientHandler, error)
}
