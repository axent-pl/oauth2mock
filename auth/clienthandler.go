package auth

type ClientHandler interface {
	Id() string
	Name() string
	RedirectURI() string
	AuthScheme() AuthenticationSchemeHandler
}

type client struct {
	id          string
	redirectURI string
	authScheme  AuthenticationSchemeHandler
}

func (c *client) Id() string {
	return c.id
}

func (c *client) Name() string {
	return c.id
}

func (c *client) RedirectURI() string {
	return c.redirectURI
}

func (c *client) AuthScheme() AuthenticationSchemeHandler {
	return c.authScheme
}
