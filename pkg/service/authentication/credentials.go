package authentication

import (
	"errors"

	e "github.com/axent-pl/oauth2mock/pkg/error"
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
			return e.ErrUserCredsMissingUsername
		}
		if password == "" {
			return e.ErrUserCredsMissingPassword
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
			return e.ErrClientCredsMissingClientId
		}
		if clientSecret == "" {
			return e.ErrClientCredsMissingClientSecret
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
			return e.ErrClientCredsMissingMissingAssertionType
		}
		if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return e.ErrClientCredsMissingInvalidAssertionType
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
	return "", errors.New("credentials do not contain identity name")
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
		return "", errors.New("credentials do not have a valid authentication method")
	}
}
