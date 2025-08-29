package tpl

import "github.com/axent-pl/oauth2mock/pkg/consentservice"

type LoginTemplateData struct {
	FormAction       string
	FormErrorMessage string
	Username         string
	UsernameError    string
	PasswordError    string
}

type AuthorizeTemplateData struct {
	FormAction       string
	FormErrorMessage string
	Username         string
	UsernameError    string
	PasswordError    string
	Consents         map[string]consentservice.Entity
}
