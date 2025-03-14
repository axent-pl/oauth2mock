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
	ErrInvalidCreds                  = errors.New("invalid credentials")
	ErrMissingCredUsernameOrPassword = &PkgError{"missing username or password", ErrInvalidCreds}
	ErrMissingCredUsername           = &PkgError{"missing username", ErrMissingCredUsernameOrPassword}
	ErrMissingCredPassword           = &PkgError{"missing password", ErrMissingCredUsernameOrPassword}

	ErrMissingCredClientId         = errors.New("missing client_id")
	ErrMissingCredClientSecret     = errors.New("missing client_secret")
	ErrMissingCredClientIdOrSecret = errors.New("missing client_id or client_secret")

	ErrMissingResponseType      = errors.New("missing response_type")
	ErrInvalidResponseType      = errors.New("invalid response_type, allowed values [code]")
	ErrInvalidClientId          = errors.New("invalid client_id")
	ErrInvalidClientRedirectURI = errors.New("invalid rediurect_uri")
)
