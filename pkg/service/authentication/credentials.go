package authentication

import (
	"github.com/axent-pl/oauth2mock/pkg/errs"
)

type CredentialsHandler interface {
	Method() AuthenticationMethod
	IdentityName() (string, error)
	Credentials() (string, error)
}

// credentialsHandler represent the credentials provided either by client or user.
type credentialsHandler struct {
	method        AuthenticationMethod
	username      string
	password      string
	clientId      string
	clientSecret  string
	assertion     string
	assertionType string
}

// CredentialsOption represent an option for NewAuthenticationCredentials - the authenticationCredentials constructor
type CredentialsOption func(*credentialsHandler) error

func NewCredentials(option CredentialsOption) (CredentialsHandler, error) {
	authCredentials := &credentialsHandler{}
	if err := option(authCredentials); err != nil {
		return nil, err
	}
	return authCredentials, nil
}

func FromUsernameAndPassword(username string, password string) CredentialsOption {
	return func(c *credentialsHandler) error {
		if username == "" {
			return errs.New("missing username", errs.ErrInvalidArgument)
		}
		if password == "" {
			return errs.New("missing password", errs.ErrInvalidArgument)
		}
		c.username = username
		c.password = password
		c.method = UserPassword
		return nil
	}
}

func FromCliendIdAndSecret(clientId string, clientSecret string) CredentialsOption {
	return func(c *credentialsHandler) error {
		if clientId == "" {
			return errs.New("missing client_id", errs.ErrInvalidArgument)
		}
		if clientSecret == "" {
			return errs.New("missing client_secret", errs.ErrInvalidArgument)
		}
		c.clientId = clientId
		c.clientSecret = clientSecret
		c.method = ClientSecret
		return nil
	}
}

func FromClientAssertion(assertionType, assertion string) CredentialsOption {
	return func(c *credentialsHandler) error {
		if assertionType == "" {
			return errs.New("missing assertion_type", errs.ErrInvalidArgument)
		}
		if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return errs.New("invalid assertion_type", errs.ErrInvalidArgument).WithDetailsf("invalid assertion type '%s'", assertionType)
		}
		c.assertionType = assertionType
		c.assertion = assertion
		c.method = ClientAssertion
		return nil
	}
}

func (c *credentialsHandler) Method() AuthenticationMethod {
	return c.method
}

func (c *credentialsHandler) IdentityName() (string, error) {
	if len(c.username) > 0 {
		return c.username, nil
	}
	if len(c.clientId) > 0 {
		return c.clientId, nil
	}
	return "", errs.New("internal error", errs.ErrInternal).WithDetails("credentials missing both username and client_id")
}

func (c *credentialsHandler) Credentials() (string, error) {
	switch c.method {
	case UserPassword:
		return c.password, nil
	case ClientSecret:
		return c.clientSecret, nil
	case ClientAssertion:
		return c.assertion, nil
	default:
		return "", errs.New("internal error", errs.ErrInternal).WithDetailsf("invalid authentication method '%s'", c.method)
	}
}
