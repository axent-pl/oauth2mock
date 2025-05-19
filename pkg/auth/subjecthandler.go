package auth

type UserHandler interface {
	Id() string
	Name() string
	Active() bool
	AuthenticationScheme() AuthenticationSchemeHandler
}
