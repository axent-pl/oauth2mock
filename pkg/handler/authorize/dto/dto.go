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
