package dto

type TokenRequestDTO struct {
	GrantType    string `formField:"grant_type" validate:"required"`
	ClientId     string `formField:"client_id"`
	ClientSecret string `formField:"client_secret"`
	Code         string `formField:"code"`
	RedirectURI  string `formField:"redirect_uri"`
	Username     string `formField:"username"`
	Password     string `formField:"password"`
	RefreshToken string `formField:"refresh_token"`
	Scope        string `formField:"scope"`
}

type TokenAuthorizationCodeRequestDTO struct {
	GrantType    string `formField:"grant_type" validate:"required"`
	ClientId     string `formField:"client_id" validate:"required"`
	ClientSecret string `formField:"client_secret" validate:"required"`
	Code         string `formField:"code" validate:"required"`
	RedirectURI  string `formField:"redirect_uri" validate:"required"`
}

type TokenClientCredentialsHandlerRequestDTO struct {
	GrantType    string `formField:"grant_type" validate:"required"`
	ClientId     string `formField:"client_id" validate:"required"`
	ClientSecret string `formField:"client_secret" validate:"required"`
	RedirectURI  string `formField:"redirect_uri"`
	Scope        string `formField:"scope"`
}

type TokenPasswrodRequestDTO struct {
	GrantType    string `formField:"grant_type" validate:"required"`
	ClientId     string `formField:"client_id" validate:"required"`
	ClientSecret string `formField:"client_secret" validate:"required"`
	RedirectURI  string `formField:"redirect_uri"`
	Username     string `formField:"username"`
	Password     string `formField:"password"`
	Scope        string `formField:"scope"`
}
