package auth

type AuthorizationRequest struct {
	ResponseType string
	RedirectURI  string
	Scope        []string
	State        string
	Client       ClientHandler
	Subject      SubjectHandler
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
		return ErrMissingResponseType
	}

	// Validate ResponseType
	if req.ResponseType != "code" {
		return ErrInvalidResponseType
	}

	// Validate RedirectURI
	if len(req.RedirectURI) > 0 && !MatchesWildcard(req.RedirectURI, req.Client.RedirectURIPattern()) {
		return ErrInvalidClientRedirectURI
	}

	return nil
}
