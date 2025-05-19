package authentication

type AuthenticationMethod string

const (
	UserPassword    AuthenticationMethod = "UserPassword"
	ClientSecret    AuthenticationMethod = "ClientSecret"
	ClientAssertion AuthenticationMethod = "ClientAssertion"
)
