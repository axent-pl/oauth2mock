package consentservice

import (
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type Entity interface {
	GetScope() string
	IsGranted() bool
	IsRevoked() bool
	IsRequired() bool

	Grant() error
	Revoke() error
	SetState(bool) error
}

type Service interface {
	GetConsents(user userservice.Entity, client clientservice.Entity, scopes []string) (map[string]Entity, error)
	SaveConsents(user userservice.Entity, client clientservice.Entity, consents []Entity) error
	ClearConsents(user userservice.Entity, client clientservice.Entity) error
}
