package template

import (
	"github.com/axent-pl/oauth2mock/dto"
	"github.com/axent-pl/oauth2mock/pkg/auth"
)

type AuthorizeTemplateData struct {
	FormAction           string
	ValidationErrors     map[string]dto.ValidationError
	AuthenticationError  string
	Credentials          dto.AuthorizeCredentialsDTO
	AuthorizationRequest *auth.AuthorizationRequest
}
