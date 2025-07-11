package tpl

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
}
