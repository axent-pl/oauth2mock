package auth

type Client struct {
	Id          string
	RedirectURI string
	authScheme  AuthenticationSchemeHandler
}
