package auth

type SubjectHandler interface {
	Name() string
	AuthenticationScheme() AuthenticationSchemeHandler
}
