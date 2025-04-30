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
		if clientId == "" {
			return ErrClientCredsMissingClientId
		}
		if clientSecret == "" {
			return ErrClientCredsMissingClientSecret
		}
		s.ClientId = clientId
		s.ClientSecret = clientSecret
		return nil
	}
}

func WithUsernameAndPassword(username, password string) AuthenticationSchemeOption {
	return func(s *authenticationScheme) error {
		if username == "" {
			return ErrUserCredsMissingUsername
		}
		if password == "" {
			return ErrUserCredsMissingPassword
		}
		s.Username = username
		s.Password = password
		return nil
	}
}

func WithClientAssertion(assertionType, assertionClaim string, assertionJWKS string) AuthenticationSchemeOption {
	return func(s *authenticationScheme) error {
		if assertionType == "" {
			return ErrClientCredsMissingMissingAssertionType
		}
		if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return ErrClientCredsMissingInvalidAssertionType
		}
		s.AssertionType = assertionType
		s.AssertionClaim = assertionClaim
		s.AssertionJWKS = assertionJWKS
		return errors.New("unsupported")
	}
}

func (s *authenticationScheme) IsValid(inputCredentials AuthenticationCredentialsHandler) bool {
	// Hacky way to access the implementation details...
	inputCredentialsImpl, ok := inputCredentials.Implementation().(authenticationCredentials)
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
