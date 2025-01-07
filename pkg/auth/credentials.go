package auth

import "errors"

type Credentials struct {
	Username      string
	Password      string
	ClientId      string
	ClientSecret  string
	Assertion     string
	AssertionType string
}

type CredentialsOption func(*Credentials) error

func NewCredentials(options ...CredentialsOption) (*Credentials, error) {
	credentials := &Credentials{}
	for _, opt := range options {
		if err := opt(credentials); err != nil {
			return nil, err
		}
	}
	return credentials, nil
}

func WithClientIdAndSecret(clientId, clientSecret string) CredentialsOption {
	return func(c *Credentials) error {
		if clientId == "" || clientSecret == "" {
			return errors.New("clientId and clientSecret must not be empty")
		}
		c.ClientId = clientId
		c.ClientSecret = clientSecret
		return nil
	}
}

func WithUsernameAndPassword(username, password string) CredentialsOption {
	return func(c *Credentials) error {
		if username == "" || password == "" {
			return errors.New("username and password must not be empty")
		}
		c.Username = username
		c.Password = password
		return nil
	}
}

func WithClientAssertion(assertionType, assertion string) CredentialsOption {
	return func(c *Credentials) error {
		if assertionType == "" || assertion == "" {
			return errors.New("assertionType and assertion must not be empty")
		}
		if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return errors.New("unsupported assertionType, allowed values [`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`]")
		}
		c.AssertionType = assertionType
		c.Assertion = assertion
		return nil
	}
}

func (c *Credentials) Match(credentials *Credentials) bool {
	if len(credentials.Username) > 0 && len(c.Username) > 0 {
		return c.Username == credentials.Username && c.Password == credentials.Password
	}
	if len(credentials.ClientId) > 0 && len(c.ClientId) > 0 {
		return c.ClientId == credentials.ClientId && c.ClientSecret == credentials.ClientSecret
	}
	return true
}
