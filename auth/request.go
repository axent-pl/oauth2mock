package auth

type AuthorizationRequest struct {
	ResponseType string
	RedirectURI  string
	Scope        string
	State        string
	Client       *Client
	Subject      *Subject
}

func (req *AuthorizationRequest) GetRedirectURI() string {
	if len(req.RedirectURI) == 0 {
		return req.Client.RedirectURI
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
	if len(req.RedirectURI) > 0 && !MatchesWildcard(req.RedirectURI, req.Client.RedirectURI) {
		return ErrInvalidClientRedirectURI
	}

	return nil
}
