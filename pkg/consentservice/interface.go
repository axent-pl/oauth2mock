package consentservice

import (
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type Consenter interface {
	GetScope() string
	IsGranted() bool
	IsRevoked() bool
	IsRequired() bool

	Grant() error
	Revoke() error
	SetState(bool) error
}

type ConsentServicer interface {
	GetConsents(user userservice.UserHandler, client clientservice.ClientHandler, scopes []string) (map[string]Consenter, error)
	SaveConsents(user userservice.UserHandler, client clientservice.ClientHandler, consents []Consenter) error
	ClearConsents(user userservice.UserHandler, client clientservice.ClientHandler) error
}
