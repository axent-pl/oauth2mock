package consentservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type jsonConsentServiceConfig struct {
	UsersWrapper struct {
		Users map[string]struct {
			Username string          `json:"username"`
			Consents map[string]bool `json:"consents"`
		} `json:"users"`
	} `json:"users"`
	Scopes []string `json:"scopes"`
}

type jsonConsentHandler struct {
	scope   string
	granted bool
}

func (h *jsonConsentHandler) GetScope() string {
	return h.scope
}
func (h *jsonConsentHandler) IsGranted() bool {
	return h.granted
}
func (h *jsonConsentHandler) IsRevoked() bool {
	return !h.granted
}
func (h *jsonConsentHandler) IsOneTime() bool {
	return false
}
func (h *jsonConsentHandler) IsExpired() bool {
	return false
}
func (h *jsonConsentHandler) GrantPersistent() error {
	h.granted = true
	return nil
}
func (h *jsonConsentHandler) GrantOnce() error {
	return errors.New("not implemented")
}
func (h *jsonConsentHandler) GrantForDuration(time.Duration) error {
	return errors.New("not implemented")
}
func (h *jsonConsentHandler) GrantUntil(time.Time) error {
	return errors.New("not implemented")
}
func (h *jsonConsentHandler) Revoke() error {
	h.granted = false
	return nil
}
func (h *jsonConsentHandler) LastUpdated() time.Time {
	return time.Now()
}

type jsonConsentService struct {
	userConsents   map[string]map[string]bool
	userConsentsMU sync.RWMutex
	scopes         map[string]string
	scopesMU       sync.RWMutex
}

func NewJSONConsentsService(rawConsentsConfig json.RawMessage, rawConfig json.RawMessage) (ConsentServicer, error) {
	slog.Info("claimservice factory NewJSONConsentsService started")
	config := jsonConsentServiceConfig{}
	service := jsonConsentService{
		userConsents: make(map[string]map[string]bool),
		scopes:       make(map[string]string),
	}

	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, err
	}

	service.userConsentsMU.Lock()
	defer service.userConsentsMU.Unlock()
	for username, userData := range config.UsersWrapper.Users {
		service.userConsents[username] = userData.Consents
	}

	service.scopesMU.Lock()
	defer service.scopesMU.Unlock()
	for _, scope := range config.Scopes {
		service.scopes[scope] = scope
	}

	return &service, nil
}

func (s *jsonConsentService) GetConsents(user userservice.UserHandler, client clientservice.ClientHandler, scopes []string) (map[string]ConsentHandler, error) {
	consents := make(map[string]ConsentHandler)
	username := user.Id()
	if userConsents, okUC := s.userConsents[username]; okUC {
		for _, scope := range scopes {
			if scopeConsentGranted, okUS := userConsents[scope]; okUS {
				consents[scope] = &jsonConsentHandler{
					scope:   scope,
					granted: scopeConsentGranted,
				}
			} else {
				consents[scope] = &jsonConsentHandler{
					scope:   scope,
					granted: false,
				}
			}
		}
	} else {
		for _, scope := range scopes {
			consents[scope] = &jsonConsentHandler{
				scope:   scope,
				granted: false,
			}
		}
	}
	return consents, nil
}

func (s *jsonConsentService) SaveConsents(user userservice.UserHandler, client clientservice.ClientHandler, consents []ConsentHandler) error {
	username := user.Id()
	if _, ok := s.userConsents[username]; !ok {
		s.userConsents[username] = make(map[string]bool)
	}
	for _, consent := range consents {
		if _, ok := s.scopes[consent.GetScope()]; !ok {
			return fmt.Errorf("scope %s is not defined", consent.GetScope())
		}
		s.userConsents[username][consent.GetScope()] = consent.IsGranted()
	}
	return nil
}
func (s *jsonConsentService) ClearConsents(user userservice.UserHandler, client clientservice.ClientHandler) error {
	username := user.Id()
	s.userConsents[username] = make(map[string]bool)
	return nil
}
