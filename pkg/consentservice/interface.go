package consentservice

import (
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type ConsentHandler interface {
	GetScope() string
	IsGranted() bool
	IsRevoked() bool
	IsRequired() bool
	Grant() error
	Revoke() error
}

type ConsentServicer interface {
	GetConsents(user userservice.UserHandler, client clientservice.ClientHandler, scopes []string) (map[string]ConsentHandler, error)
	SaveConsents(user userservice.UserHandler, client clientservice.ClientHandler, consents []ConsentHandler) error
	ClearConsents(user userservice.UserHandler, client clientservice.ClientHandler) error
}
