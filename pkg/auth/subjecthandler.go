package auth

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type UserHandler interface {
	Id() string
	Name() string
	Active() bool
	AuthenticationScheme() authentication.SchemeHandler
}
