package auth

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type ClientHandler interface {
	Id() string
	Name() string
	RedirectURIPattern() string
	AuthenticationScheme() authentication.SchemeHandler
	ValidateRedirectURI(redirectURI string) bool
}

type client struct {
	id                 string
	redirectURIPattern string
	authScheme         authentication.SchemeHandler
}

func (c *client) Id() string {
	return c.id
}

func (c *client) Name() string {
	return c.id
}

func (c *client) RedirectURIPattern() string {
	return c.redirectURIPattern
}

// Validates the given redirectURI against client's configuration
func (c *client) ValidateRedirectURI(redirectURI string) bool {
	return (len(redirectURI) > 0) && MatchesWildcard(redirectURI, c.redirectURIPattern)
}

func (c *client) AuthenticationScheme() authentication.SchemeHandler {
	return c.authScheme
}
