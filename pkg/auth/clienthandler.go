package auth

type ClientHandler interface {
	Id() string
	Name() string
	RedirectURIPattern() string
	AuthenticationScheme() AuthenticationSchemeHandler
	ValidateRedirectURI(redirectURI string) bool
}

type client struct {
	id                 string
	redirectURIPattern string
	authScheme         AuthenticationSchemeHandler
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

func (c *client) AuthenticationScheme() AuthenticationSchemeHandler {
	return c.authScheme
}
