package auth

import (
	"errors"
)

var (
	ErrInvalidCreds             = errors.New("invalid username or password")
	ErrMissingResponseType      = errors.New("missing response_type")
	ErrInvalidResponseType      = errors.New("invalid response_type, allowed values [code]")
	ErrMissingClientId          = errors.New("missing client_id")
	ErrInvalidClientId          = errors.New("invalid client_id")
	ErrInvalidClientRedirectURI = errors.New("invalid rediurect_uri")
)
