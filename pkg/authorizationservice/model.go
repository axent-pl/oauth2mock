package authorizationservice

import (
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type authorizationRequest struct {
	ResponseType string
	RedirectURI  string
	Scopes       []string
	State        string
	Nonce        string
	Client       clientservice.ClientHandler
	User         userservice.UserHandler
}

type NewAuthorizationRequestOption func(*authorizationRequest) error

func WithRedirectURI(redirectURI string) NewAuthorizationRequestOption {
	return func(req *authorizationRequest) error {
		req.RedirectURI = redirectURI
		return nil
	}
}

func WithState(state string) NewAuthorizationRequestOption {
	return func(req *authorizationRequest) error {
		req.State = state
		return nil
	}
}

func WithNonce(nonce string) NewAuthorizationRequestOption {
	return func(req *authorizationRequest) error {
		req.Nonce = nonce
		return nil
	}
}

func WithUser(user userservice.UserHandler) NewAuthorizationRequestOption {
	return func(req *authorizationRequest) error {
		req.User = user
		return nil
	}
}

func NewAuthorizationRequest(responseType string, scopes []string, client clientservice.ClientHandler, options ...NewAuthorizationRequestOption) (AuthorizationRequester, error) {
	req := &authorizationRequest{
		ResponseType: responseType,
		Scopes:       scopes,
		Client:       client,
	}
	for _, opt := range options {
		if err := opt(req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (req *authorizationRequest) GetResponseType() string {
	return req.ResponseType
}

func (req *authorizationRequest) GetRedirectURI() string {
	if len(req.RedirectURI) == 0 {
		return req.Client.RedirectURIPattern()
	}
	return req.RedirectURI
}

func (req *authorizationRequest) GetScopes() []string {
	return req.Scopes
}

func (req *authorizationRequest) GetState() string {
	return req.State
}

func (req *authorizationRequest) GetNonce() string {
	return req.Nonce
}

func (req *authorizationRequest) GetClient() clientservice.ClientHandler {
	return req.Client
}

func (req *authorizationRequest) GetUser() userservice.UserHandler {
	return req.User
}
