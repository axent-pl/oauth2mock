package auth

import (
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/errs"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type AuthorizationRequest struct {
	ResponseType string
	RedirectURI  string
	Scope        []string
	State        string
	Nonce        string
	Client       clientservice.ClientHandler
	Subject      userservice.UserHandler
}

func (req *AuthorizationRequest) GetRedirectURI() string {
	if len(req.RedirectURI) == 0 {
		return req.Client.RedirectURIPattern()
	}
	return req.RedirectURI
}

func (req *AuthorizationRequest) Valid() error {
	// Validate required
	if len(req.ResponseType) == 0 {
		return errs.ErrMissingResponseType
	}

	// Validate ResponseType
	if req.ResponseType != "code" {
		return errs.ErrInvalidResponseType
	}

	// Validate RedirectURI
	if len(req.RedirectURI) > 0 && !MatchesWildcard(req.RedirectURI, req.Client.RedirectURIPattern()) {
		return errs.ErrInvalidClientRedirectURI
	}

	return nil
}
