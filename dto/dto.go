package dto

type AuthorizeCredentialsDTO struct {
	Username string `formField:"username" validate:"required"`
	Password string `formField:"password" validate:"required"`
}

type AuthorizeRequestDTO struct {
	ResponseType string `queryParam:"response_type" validate:"required"`
	ClientId     string `queryParam:"client_id" validate:"required"`
	RedirectURI  string `queryParam:"redirect_uri"`
	Scope        string `queryParam:"scope"`
	State        string `queryParam:"state"`
}

type TokenRequestDTO struct {
	GrantType    string `formField:"grant_type" validate:"required"`
	ClientId     string `formField:"client_id"`
	ClientSecret string `formField:"client_secret"`
	Code         string `formField:"code"`
	RedirectURI  string `formField:"redirect_uri"`
	Username     string `formField:"username"`
	Password     string `formField:"password"`
	RefreshToken string `formField:"refresh_token"`
}

type AuthorizationCodeTokenRequestDTO struct {
	GrantType    string `formField:"grant_type" validate:"required"`
	ClientId     string `formField:"client_id" validate:"required"`
	ClientSecret string `formField:"client_secret" validate:"required"`
	Code         string `formField:"code" validate:"required"`
	RedirectURI  string `formField:"redirect_uri" validate:"required"`
	Username     string `formField:"username"`
	Password     string `formField:"password"`
	RefreshToken string `formField:"refresh_token"`
}

type ClientCredentialsTokenRequestDTO struct {
	GrantType    string `formField:"grant_type" validate:"required"`
	ClientId     string `formField:"client_id" validate:"required"`
	ClientSecret string `formField:"client_secret" validate:"required"`
	Code         string `formField:"code"`
	RedirectURI  string `formField:"redirect_uri"`
	Username     string `formField:"username"`
	Password     string `formField:"password"`
	RefreshToken string `formField:"refresh_token"`
}
