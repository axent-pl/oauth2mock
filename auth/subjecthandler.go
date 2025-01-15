package auth

type SubjectHandler interface {
	Name() string
	AuthScheme() AuthenticationSchemeHandler
}

type subject struct {
	name       string
	authScheme AuthenticationSchemeHandler
}

func (s *subject) Name() string {
	return s.name
}

func (s *subject) AuthScheme() AuthenticationSchemeHandler {
	return s.authScheme
}
