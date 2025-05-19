package auth

type userHandler struct {
	name       string
	authScheme AuthenticationSchemeHandler
}

func (s *userHandler) Id() string {
	return s.name
}

func (s *userHandler) Name() string {
	return s.name
}

func (s *userHandler) Active() bool {
	return true
}

func (s *userHandler) AuthenticationScheme() AuthenticationSchemeHandler {
	return s.authScheme
}
