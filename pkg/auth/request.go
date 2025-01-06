package auth

type AuthorizationRequest struct {
	ResponseType string
	RedirectURI  string
	Scope        string
	State        string
	Client       *Client
	Subject      *Subject
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
	if len(req.RedirectURI) == 0 {
		req.RedirectURI = req.Client.RedirectURI
	} else if req.RedirectURI != req.Client.RedirectURI {
		return ErrInvalidClientRedirectURI
	}

	return nil
}
