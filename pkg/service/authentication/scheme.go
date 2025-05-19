package authentication

import (
	"errors"
	"log/slog"

	e "github.com/axent-pl/oauth2mock/pkg/error"
)

type SchemeHandler interface {
	IsValid(inputCredentials CredentialsHandler) bool
}

// schemeHandler represents the configuration for multiple authentication methods.
type schemeHandler struct {
	Username       string // For basic authentication
	Password       string
	ClientId       string // For client credentials
	ClientSecret   string
	AssertionType  string // e.g., urn:ietf:params:oauth:client-assertion-type:jwt-bearer
	AssertionClaim string // Path to claim containing the identity (username or client_id)
	AssertionJWKS  string // URL to trusted issuer's JWKS
}

type SchemeOption func(*schemeHandler) error

func NewScheme(options ...SchemeOption) (SchemeHandler, error) {
	scheme := &schemeHandler{}
	for _, opt := range options {
		if err := opt(scheme); err != nil {
			return nil, err
		}
	}
	return scheme, nil
}

func WithClientIdAndSecret(clientId, clientSecret string) SchemeOption {
	return func(s *schemeHandler) error {
		if clientId == "" {
			return e.ErrClientCredsMissingClientId
		}
		if clientSecret == "" {
			return e.ErrClientCredsMissingClientSecret
		}
		clientSecretHash, err := HashPassword(clientSecret)
		if err != nil {
			return err
		}
		s.ClientId = clientId
		s.ClientSecret = clientSecretHash
		return nil
	}
}

func WithUsernameAndPassword(username, password string) SchemeOption {
	return func(s *schemeHandler) error {
		if username == "" {
			return e.ErrUserCredsMissingUsername
		}
		if password == "" {
			return e.ErrUserCredsMissingPassword
		}
		passwordHash, err := HashPassword(password)
		if err != nil {
			return err
		}
		s.Username = username
		s.Password = passwordHash
		return nil
	}
}

func WithClientAssertion(assertionType, assertionClaim string, assertionJWKS string) SchemeOption {
	return func(s *schemeHandler) error {
		if assertionType == "" {
			return e.ErrClientCredsMissingMissingAssertionType
		}
		if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return e.ErrClientCredsMissingInvalidAssertionType
		}
		s.AssertionType = assertionType
		s.AssertionClaim = assertionClaim
		s.AssertionJWKS = assertionJWKS
		return errors.New("unsupported")
	}
}

func (s *schemeHandler) IsValid(inputCredentials CredentialsHandler) bool {
	identity, err := inputCredentials.IdentityName()
	if err != nil {
		return false
	}
	credentials, err := inputCredentials.Credentials()
	if err != nil {
		return false
	}

	switch inputCredentials.Method() {
	case UserPassword:
		if s.Username != identity {
			slog.Error("username does not match")
			return false
		}
		if credentialsMatch, err := CheckPasswordHash(credentials, s.Password); !credentialsMatch || err != nil {
			slog.Error("password does not match", "credentials", credentials, "s.Password", s.Password)
			return false
		}
		return true
	case ClientSecret:
		if s.ClientId != identity {
			return false
		}
		if credentialsMatch, err := CheckPasswordHash(credentials, s.ClientSecret); !credentialsMatch || err != nil {
			slog.Error("client secret does not match", "credentials", credentials)
			return false
		}
		return true
	case ClientAssertion:
		return false
	default:
		return false
	}
}
