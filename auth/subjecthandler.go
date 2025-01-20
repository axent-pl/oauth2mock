package auth

type SubjectHandler interface {
	Name() string
	AuthScheme() AuthenticationSchemeHandler
}
