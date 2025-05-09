package auth

import (
	"errors"
)

type PkgError struct {
	msg  string
	kind error
}

func (e *PkgError) Error() string {
	return e.msg
}

func (e *PkgError) Unwrap() error {
	return e.kind
}

func (e *PkgError) Is(target error) bool {
	return errors.Is(e.kind, target)
}

var (
	ErrUserCredsInvalid                   = errors.New("invalid user credentials")
	ErrUserCredsMissingUsernameOrPassword = &PkgError{"missing username or password", ErrUserCredsInvalid}
	ErrUserCredsMissingUsername           = &PkgError{"missing username", ErrUserCredsMissingUsernameOrPassword}
	ErrUserCredsMissingPassword           = &PkgError{"missing password", ErrUserCredsMissingUsernameOrPassword}

	ErrClientCredsMissingClientIdOrSecret     = errors.New("missing client_id or client_secret")
	ErrClientCredsMissingClientId             = &PkgError{"missing client_id", ErrClientCredsMissingClientIdOrSecret}
	ErrClientCredsMissingClientSecret         = &PkgError{"missing client_secret", ErrClientCredsMissingClientIdOrSecret}
	ErrClientCredsMissingMissingAssertionType = errors.New("assertionType must not be empty")
	ErrClientCredsMissingInvalidAssertionType = errors.New("unsupported assertionType, allowed values [`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`]")

	ErrMissingResponseType      = errors.New("missing response_type")
	ErrInvalidResponseType      = errors.New("invalid response_type, allowed values [code]")
	ErrInvalidClientId          = errors.New("invalid client_id")
	ErrInvalidClientRedirectURI = errors.New("invalid rediurect_uri")
)
