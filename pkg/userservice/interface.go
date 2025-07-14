package userservice

import "github.com/axent-pl/oauth2mock/pkg/service/authentication"

type Entity interface {
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

type Service interface {
	Authenticate(credentials authentication.CredentialsHandler) (Entity, error)
	GetUsers() ([]Entity, error)
	AddUser(Entity) error
}
