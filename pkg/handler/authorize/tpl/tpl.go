package tpl

import (
	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/handler/authorize/dto"
	"github.com/axent-pl/oauth2mock/pkg/http/request"
)

type AuthorizeTemplateData struct {
	FormAction           string
	ValidationErrors     map[string]request.ValidationError
	AuthenticationError  string
	Credentials          dto.AuthorizeCredentialsDTO
	AuthorizationRequest *auth.AuthorizationRequest
}
