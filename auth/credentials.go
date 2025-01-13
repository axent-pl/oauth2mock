package auth

import (
	"errors"
)

type credentials struct {
	Username      string
	Password      string
	ClientId      string
	ClientSecret  string
	Assertion     string
	AssertionType string
}

type CredentialsService interface {
	Match(inputCredentials CredentialsService) bool
	UsernamePasswordHash() string
	ClientIdSecretHash() string
}

type CredentialsOption func(*credentials) error

func NewCredentials(options ...CredentialsOption) (CredentialsService, error) {
	credentials := &credentials{}
	for _, opt := range options {
		if err := opt(credentials); err != nil {
			return nil, err
		}
	}
	return credentials, nil
}

func WithClientIdAndSecret(clientId, clientSecret string) CredentialsOption {
	return func(c *credentials) error {
		if clientId == "" || clientSecret == "" {
			return errors.New("clientId and clientSecret must not be empty")
		}
		c.ClientId = clientId
		c.ClientSecret = clientSecret
		return nil
	}
}

func WithUsernameAndPassword(username, password string) CredentialsOption {
	return func(c *credentials) error {
		if username == "" || password == "" {
			return errors.New("username and password must not be empty")
		}
		c.Username = username
		c.Password = password
		return nil
	}
}

func WithClientAssertion(assertionType, assertion string) CredentialsOption {
	return func(c *credentials) error {
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

func (c *credentials) UsernamePasswordHash() string {
	return c.Username + ":" + c.Password
}

func (c *credentials) ClientIdSecretHash() string {
	return c.ClientId + ":" + c.ClientSecret
}

func (c *credentials) Match(inputCredentials CredentialsService) bool {
	if len(c.Username) > 0 {
		return c.UsernamePasswordHash() == inputCredentials.UsernamePasswordHash()
	}
	if len(c.ClientId) > 0 {
		return c.ClientIdSecretHash() == inputCredentials.ClientIdSecretHash()
	}
	return false
}
