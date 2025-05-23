package errs

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

func New(msg string, kind *PkgError) *PkgError {
	return &PkgError{msg, kind}
}

var (
	Err                                   = errors.New("undefined error")
	ErrUserCredsInvalid                   = &PkgError{"invalid user credentials", Err}
	ErrUserCredsMissingUsernameOrPassword = &PkgError{"missing username or password", ErrUserCredsInvalid}
	ErrUserCredsMissingUsername           = &PkgError{"missing username", ErrUserCredsMissingUsernameOrPassword}
	ErrUserCredsMissingPassword           = &PkgError{"missing password", ErrUserCredsMissingUsernameOrPassword}

	ErrClientCredsMissingClientIdOrSecret     = &PkgError{"missing client_id or client_secret", Err}
	ErrClientCredsMissingClientId             = &PkgError{"missing client_id", ErrClientCredsMissingClientIdOrSecret}
	ErrClientCredsMissingClientSecret         = &PkgError{"missing client_secret", ErrClientCredsMissingClientIdOrSecret}
	ErrClientCredsMissingMissingAssertionType = &PkgError{"assertionType must not be empty", Err}
	ErrClientCredsMissingInvalidAssertionType = &PkgError{"unsupported assertionType, allowed values [`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`]", Err}

	ErrCredsMissingIdentity     = &PkgError{"missing identity in credentials (client_id or username)", Err}
	ErrCredsUndefinedAuthMethod = &PkgError{"undefined authentication method (password, client_secret, ...)", Err}

	ErrMissingResponseType      = &PkgError{"missing response_type", Err}
	ErrInvalidResponseType      = &PkgError{"invalid response_type, allowed values [code]", Err}
	ErrInvalidClientId          = &PkgError{"invalid client_id", Err}
	ErrInvalidClientRedirectURI = &PkgError{"invalid rediurect_uri", Err}

	ErrUnsupportedFeature = &PkgError{"feature unsupported", Err}
)
