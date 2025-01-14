package auth

type SubjectHandler interface {
	Name() string
	Credentials() AuthenticationSchemeHandler
}

type subject struct {
	name       string
	authScheme AuthenticationSchemeHandler
}

func (s *subject) Name() string {
	return s.name
}

func (s *subject) Credentials() AuthenticationSchemeHandler {
	return s.authScheme
}
