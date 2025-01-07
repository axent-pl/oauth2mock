package template

import (
	"github.com/axent-pl/oauth2mock/auth"
	"github.com/axent-pl/oauth2mock/dto"
)

type AuthorizeTemplateData struct {
	FormAction           string
	ValidationErrors     map[string]dto.ValidationError
	AuthenticationError  string
	Credentials          dto.AuthorizeCredentialsDTO
	AuthorizationRequest *auth.AuthorizationRequest
}
