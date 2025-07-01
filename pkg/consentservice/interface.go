package consentservice

import (
	"time"

	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type ConsentHandler interface {
	GetScope() string
	IsGranted() bool // returns true if currently usable
	IsRevoked() bool // returns true if explicitly denied
	IsOneTime() bool // true if granted once only
	IsExpired() bool // true if time-based and expired

	GrantPersistent() error
	GrantOnce() error
	GrantForDuration(time.Duration) error
	GrantUntil(time.Time) error

	Revoke() error
	LastUpdated() time.Time
}

type ConsentServicer interface {
	GetConsents(user userservice.UserHandler, client clientservice.ClientHandler, scopes []string) (map[string]ConsentHandler, error)
	SaveConsents(user userservice.UserHandler, client clientservice.ClientHandler, consents []ConsentHandler) error
	ClearConsents(user userservice.UserHandler, client clientservice.ClientHandler) error
}
