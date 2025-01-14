package auth

import (
	"errors"
	"log/slog"
)

type AuthenticationSchemeHandler interface {
	IsValid(inputCredentials AuthenticationCredentialsHandler) bool
}

// authenticationScheme represents the configuration for multiple authentication methods.
type authenticationScheme struct {
	Username       string // For basic authentication
	Password       string
	ClientId       string // For client credentials
	ClientSecret   string
	AssertionType  string // e.g., urn:ietf:params:oauth:client-assertion-type:jwt-bearer
	AssertionClaim string // Path to claim containing the identity (username or client_id)
	AssertionJWKS  string // URL to trusted issuer's JWKS
}

type AuthenticationSchemeOption func(*authenticationScheme) error

func NewAuthenticationScheme(options ...AuthenticationSchemeOption) (AuthenticationSchemeHandler, error) {
	scheme := &authenticationScheme{}
	for _, opt := range options {
		if err := opt(scheme); err != nil {
			return nil, err
		}
	}
	return scheme, nil
}

func WithClientIdAndSecret(clientId, clientSecret string) AuthenticationSchemeOption {
	return func(s *authenticationScheme) error {
		if clientId == "" || clientSecret == "" {
			return errors.New("clientId and clientSecret must not be empty")
		}
		s.ClientId = clientId
		s.ClientSecret = clientSecret
		return nil
	}
}

func WithUsernameAndPassword(username, password string) AuthenticationSchemeOption {
	return func(s *authenticationScheme) error {
		if username == "" || password == "" {
			return errors.New("username and password must not be empty")
		}
		s.Username = username
		s.Password = password
		return nil
	}
}

func WithClientAssertion(assertionType, assertionClaim string, assertionJWKS string) AuthenticationSchemeOption {
	return func(s *authenticationScheme) error {
		if assertionType == "" {
			return errors.New("assertionType must not be empty")
		}
		if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return errors.New("unsupported assertionType, allowed values [`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`]")
		}
		s.AssertionType = assertionType
		s.AssertionClaim = assertionClaim
		s.AssertionJWKS = assertionJWKS
		return errors.New("unsupported")
	}
}

func (s *authenticationScheme) IsValid(inputCredentials AuthenticationCredentialsHandler) bool {
	inputCredentialsImpl, ok := inputCredentials.Impl().(authenticationCredentials)
	if !ok {
		slog.Error("could not cast CredentialsHandler to credentials")
	}
	if len(inputCredentialsImpl.Username) > 0 && len(inputCredentialsImpl.Password) > 0 {
		return s.Username == inputCredentialsImpl.Username && s.Password == inputCredentialsImpl.Password
	}
	if len(inputCredentialsImpl.ClientId) > 0 && len(inputCredentialsImpl.ClientSecret) > 0 {
		return s.ClientId == inputCredentialsImpl.ClientId && s.ClientSecret == inputCredentialsImpl.ClientSecret
	}
	return false
}
