package auth

import "errors"

type AuthenticationCredentialsHandler interface {
	IdentityName() (string, error)
	Implementation() interface{}
}

// authenticationCredentials represent the credentials provided either by client or user.
type authenticationCredentials struct {
	Username      string
	Password      string
	ClientId      string
	ClientSecret  string
	Assertion     string
	AssertionType string
}

// AuthenticationCredentialsOption represent an option for NewAuthenticationCredentials - the authenticationCredentials constructor
type AuthenticationCredentialsOption func(*authenticationCredentials) error

func FromUsernameAndPassword(username string, password string) AuthenticationCredentialsOption {
	return func(c *authenticationCredentials) error {
		if username == "" || password == "" {
			return errors.New("username and password must not be empty")
		}
		c.Username = username
		c.Password = password
		return nil
	}
}

func FromCliendIdAndSecret(clientId string, clientSecret string) AuthenticationCredentialsOption {
	return func(c *authenticationCredentials) error {
		if clientId == "" || clientSecret == "" {
			return errors.New("clientId and clientSecret must not be empty")
		}
		c.ClientId = clientId
		c.ClientSecret = clientSecret
		return nil
	}
}

func NewAuthenticationCredentials(option AuthenticationCredentialsOption) (AuthenticationCredentialsHandler, error) {
	authCredentials := &authenticationCredentials{}
	if err := option(authCredentials); err != nil {
		return nil, err
	}
	return authCredentials, nil
}

func (c *authenticationCredentials) IdentityName() (string, error) {
	if len(c.Username) > 0 {
		return c.Username, nil
	}
	if len(c.ClientId) > 0 {
		return c.ClientId, nil
	}
	return "", errors.New("credentials do not contain identity name")
}

func (c *authenticationCredentials) Implementation() interface{} {
	return *c
}
