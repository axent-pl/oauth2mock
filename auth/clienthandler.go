package auth

type Client struct {
	Id          string
	RedirectURI string
	authScheme  AuthenticationSchemeHandler
}

func (c *Client) Name() string {
	return c.Id
}

func (c *Client) AuthScheme() AuthenticationSchemeHandler {
	return c.authScheme
}
