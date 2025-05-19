package auth

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type userHandler struct {
	name       string
	authScheme authentication.SchemeHandler
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

func (s *userHandler) AuthenticationScheme() authentication.SchemeHandler {
	return s.authScheme
}
