package userservice

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type UserHandler interface {
	Id() string
	Name() string
	SetName(string)
	Active() bool
	SetActive(bool)
	AuthenticationScheme() authentication.SchemeHandler
	SetAuthenticationScheme(authentication.SchemeHandler)
	GetAllAttributes() map[string]map[string]interface{}
	SetAllAttributes(map[string]map[string]interface{})
	GetAttributesGroup(group string) map[string]interface{}
	SetAttributesGroup(group string, value map[string]interface{})
}

type UserServicer interface {
	Authenticate(credentials authentication.CredentialsHandler) (UserHandler, error)
	GetUsers() ([]UserHandler, error)
	AddUser(UserHandler) error
}
