package auth

type subject struct {
	name       string
	authScheme AuthenticationSchemeHandler
}

func (s *subject) Name() string {
	return s.name
}

func (s *subject) AuthenticationScheme() AuthenticationSchemeHandler {
	return s.authScheme
}
