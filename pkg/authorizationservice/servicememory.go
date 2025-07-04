package authorizationservice

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/errs"
)

type memoryAuthorizationServiceConfig struct {
	Provider   string `json:"provider"`
	TTLSeconds int    `json:"authorizationRequestTTLSeconds"`
	CodeLength int    `json:"authorizationCodeLength"`
}

type memoryAuthorizationService struct {
	ttl        time.Duration
	ticker     time.Duration
	codeLength int
	requests   map[string]authorizationServiceItem
	requestsMU sync.RWMutex
}

type authorizationServiceItem struct {
	expiresAt time.Time
	request   AuthorizationRequester
}

func NewMemoryAuthorizationService(rawAuthorizationConfig json.RawMessage, rawConfig json.RawMessage) (AuthorizationServicer, error) {
	slog.Info("authorizationservice factory NewAuthorizationServiceMemory started")
	config := memoryAuthorizationServiceConfig{}
	service := memoryAuthorizationService{
		requests: make(map[string]authorizationServiceItem),
	}

	if err := json.Unmarshal(rawAuthorizationConfig, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authorization service config: %w", err)
	}

	service.codeLength = config.CodeLength
	service.ttl = time.Second * time.Duration(config.TTLSeconds)
	service.ticker = time.Second * time.Duration(config.TTLSeconds) * 10

	go service.cleanupExpiredCodes()

	return &service, nil
}

func (s *memoryAuthorizationService) Validate(authRequest AuthorizationRequester) error {
	if len(authRequest.GetResponseType()) == 0 {
		return errs.ErrMissingResponseType
	}

	if !MatchesWildcard(authRequest.GetRedirectURI(), authRequest.GetClient().RedirectURIPattern()) {
		return errs.ErrInvalidClientRedirectURI
	}

	return nil
}

func (s *memoryAuthorizationService) Store(authRequest AuthorizationRequester) (string, error) {
	s.requestsMU.Lock()
	defer s.requestsMU.Unlock()

	code, err := GenerateRandomCode(s.codeLength)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}

	s.requests[code] = authorizationServiceItem{
		expiresAt: time.Now().Add(s.ttl),
		request:   authRequest,
	}

	return code, nil
}

func (s *memoryAuthorizationService) Get(code string) (AuthorizationRequester, error) {
	s.requestsMU.Lock()
	defer s.requestsMU.Unlock()

	authRequestData, exists := s.requests[code]
	if !exists {
		return nil, fmt.Errorf("invalid authorization code %s", code)
	}
	if time.Now().After(authRequestData.expiresAt) {
		return nil, fmt.Errorf("authorization code %s has expired", code)
	}

	delete(s.requests, code)

	return authRequestData.request, nil
}

func (s *memoryAuthorizationService) cleanupExpiredCodes() {
	ticker := time.NewTicker(s.ticker)
	defer ticker.Stop()

	for range ticker.C {
		s.requestsMU.Lock()
		for code, authRequestData := range s.requests {
			if time.Now().After(authRequestData.expiresAt) {
				delete(s.requests, code)
			}
		}
		s.requestsMU.Unlock()
	}
}

func init() {
	Register("memory", NewMemoryAuthorizationService)
}
