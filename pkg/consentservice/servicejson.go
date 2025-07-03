package consentservice

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

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
	Consents struct {
		Scopes map[string]struct {
			RequireConsent bool `json:"requireConsent"`
		} `json:"scopes"`
	} `json:"consents"`
}

type jsonConsentServiceScopeMeta struct {
	requireConsent bool
}

type jsonConsentService struct {
	userConsents   map[string]map[string]bool
	userConsentsMU sync.RWMutex
	scopes         map[string]jsonConsentServiceScopeMeta
	scopesMU       sync.RWMutex
}

func NewJSONConsentsService(rawConsentsConfig json.RawMessage, rawConfig json.RawMessage) (ConsentServicer, error) {
	slog.Info("claimservice factory NewJSONConsentsService started")
	config := jsonConsentServiceConfig{}
	service := jsonConsentService{
		userConsents: make(map[string]map[string]bool),
		scopes:       make(map[string]jsonConsentServiceScopeMeta),
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
	for scope, meta := range config.Consents.Scopes {
		service.scopes[scope] = jsonConsentServiceScopeMeta{requireConsent: meta.RequireConsent}
	}

	return &service, nil
}

func (s *jsonConsentService) getUserConsentState(username string, scope string) (bool, bool) {
	if _, ok := s.userConsents[username]; !ok {
		return false, false
	}
	if _, ok := s.userConsents[username][scope]; !ok {
		return false, false
	}
	return true, s.userConsents[username][scope]
}

func (s *jsonConsentService) GetConsents(user userservice.UserHandler, client clientservice.ClientHandler, scopes []string) (map[string]Consenter, error) {
	consents := make(map[string]Consenter)
	username := user.Id()

	for _, scope := range scopes {
		if _, ok := s.scopes[scope]; !ok {
			return consents, fmt.Errorf("undefined scope %s", scope)
		}
		consent, err := NewConsent(scope, WithRequired(s.scopes[scope].requireConsent))
		if err != nil {
			return consents, fmt.Errorf("could not initialize consent for scope %s: %w", scope, err)
		}
		if exists, state := s.getUserConsentState(username, scope); exists {
			consent.SetState(state)
		}
		consents[scope] = consent
	}

	return consents, nil
}

func (s *jsonConsentService) SaveConsents(user userservice.UserHandler, client clientservice.ClientHandler, consents []Consenter) error {
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

func init() {
	Register("json", NewJSONConsentsService)
}
