package claimservice

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/consentservice"
	"github.com/axent-pl/oauth2mock/pkg/di"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type Purpose string

const (
	PurposeIDToken  Purpose = "id"
	PurposeAccess   Purpose = "access"
	PurposeRefresh  Purpose = "refresh"
	PurposeUserInfo Purpose = "userinfo"
)

// ----- Config structs -----

type jsonClaimServiceConfig struct {
	UsersWrapper struct {
		Users map[string]struct {
			Claims jsonClaimsSet `json:"claims"`
		} `json:"users"`
	} `json:"users"`
	Clients map[string]struct {
		Claims jsonClaimsSet `json:"claims"`
	} `json:"clients"`
}

// A single "layer" of claims.
type jsonClaims struct {
	Base            map[string]interface{}            `json:"base"`
	ClientOverrides map[string]map[string]interface{} `json:"clientOverrides"`
	ScopeOverrides  map[string]map[string]interface{} `json:"scopeOverrides"`
}

// A set of claims: defaults + per-purpose overrides.
// Example JSON:
//
//	"claims": {
//	  "default": { ...jsonClaims... },
//	  "byPurpose": {
//	    "id": { ...jsonClaims... },
//	    "access": { ...jsonClaims... },
//	    "refresh": { ...jsonClaims... },
//	    "userinfo": { ...jsonClaims... }
//	  }
//	}
type jsonClaimsSet struct {
	Default   jsonClaims            `json:"default"`
	ByPurpose map[string]jsonClaims `json:"byPurpose"`
}

// ----- Service impl -----

type jsonClaimService struct {
	consentService consentservice.Service

	userClaims     map[string]jsonClaimsSet // key: userId
	userClaimsMU   sync.RWMutex
	clientClaims   map[string]jsonClaimsSet // key: clientName
	clientClaimsMU sync.RWMutex
}

func NewJSONClaimsService(rawClaimsConfig json.RawMessage, rawConfig json.RawMessage) (Service, error) {
	slog.Info("claimservice factory NewJSONClaimsService started")
	config := jsonClaimServiceConfig{}
	service := &jsonClaimService{
		userClaims:   make(map[string]jsonClaimsSet),
		clientClaims: make(map[string]jsonClaimsSet),
	}

	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, err
	}

	service.userClaimsMU.Lock()
	for username, userData := range config.UsersWrapper.Users {
		service.userClaims[username] = normalizeClaimsSet(userData.Claims)
	}
	service.userClaimsMU.Unlock()

	service.clientClaimsMU.Lock()
	for clientId, clientData := range config.Clients {
		service.clientClaims[clientId] = normalizeClaimsSet(clientData.Claims)
	}
	service.clientClaimsMU.Unlock()

	di.Register(service)
	return service, nil
}

func (s *jsonClaimService) InjectConsentService(cs consentservice.Service) {
	s.consentService = cs
}

// GetClientClaims now accepts a purpose: "id", "access", "refresh", "userinfo".
func (s *jsonClaimService) GetClientClaims(client clientservice.Entity, scope []string, purpose string) (map[string]interface{}, error) {
	s.clientClaimsMU.RLock()
	defer s.clientClaimsMU.RUnlock()

	claims := make(map[string]interface{})

	clientClaimsSet, ok := s.clientClaims[client.Name()]
	if !ok {
		return claims, fmt.Errorf("no claims for client %s", client.Name())
	}

	// 1) Apply defaults
	applyLayer(claims, clientClaimsSet.Default.Base)

	// 2) Apply default client overrides
	if ov := clientClaimsSet.Default.ClientOverrides[client.Id()]; ov != nil {
		applyLayer(claims, ov)
	}

	// 3) Apply default scope overrides
	for _, scopeItem := range scope {
		if ov := clientClaimsSet.Default.ScopeOverrides[scopeItem]; ov != nil {
			applyLayer(claims, ov)
		}
	}

	// 4) Apply purpose-specific overrides (win on conflicts)
	if pLayer, ok := clientClaimsSet.ByPurpose[purpose]; ok {
		applyLayer(claims, pLayer.Base)

		if ov := pLayer.ClientOverrides[client.Id()]; ov != nil {
			applyLayer(claims, ov)
		}
		for _, scopeItem := range scope {
			if ov := pLayer.ScopeOverrides[scopeItem]; ov != nil {
				applyLayer(claims, ov)
			}
		}
	}

	return claims, nil
}

// GetUserClaims now accepts a purpose: "id", "access", "refresh", "userinfo".
func (s *jsonClaimService) GetUserClaims(user userservice.Entity, client clientservice.Entity, scopes []string, purpose string) (map[string]interface{}, error) {
	s.userClaimsMU.RLock()
	defer s.userClaimsMU.RUnlock()

	claims := make(map[string]interface{})

	consents, err := s.consentService.GetConsents(user, client, scopes)
	if err != nil {
		return nil, fmt.Errorf("could not get consents: %w", err)
	}

	userClaimsSet, ok := s.userClaims[user.Id()]
	if !ok {
		return claims, fmt.Errorf("no claims for user %s", user.Name())
	}

	// 1) Apply defaults
	applyLayer(claims, userClaimsSet.Default.Base)

	// 2) Default client overrides
	if ov := userClaimsSet.Default.ClientOverrides[client.Id()]; ov != nil {
		applyLayer(claims, ov)
	}

	// 3) Default scope overrides (only granted)
	grantedScopes := make([]string, 0)
	for _, scope := range scopes {
		scopeConsent, ok := consents[scope]
		if !ok {
			return nil, fmt.Errorf("undefined scope %s", scope)
		}
		if scopeConsent.IsGranted() {
			grantedScopes = append(grantedScopes, scope)
			if ov := userClaimsSet.Default.ScopeOverrides[scope]; ov != nil {
				applyLayer(claims, ov)
			}
		}
	}

	// 4) Purpose-specific overrides (win on conflicts)
	if pLayer, ok := userClaimsSet.ByPurpose[purpose]; ok {
		applyLayer(claims, pLayer.Base)
		if ov := pLayer.ClientOverrides[client.Id()]; ov != nil {
			applyLayer(claims, ov)
		}
		for _, scope := range scopes {
			// only granted ones again
			if consent, ok := consents[scope]; ok && consent.IsGranted() {
				if ov := pLayer.ScopeOverrides[scope]; ov != nil {
					applyLayer(claims, ov)
				}
			}
		}
	}

	claims["scope"] = strings.Join(grantedScopes, " ")
	return claims, nil
}

func init() {
	Register("json", NewJSONClaimsService)
}

// ----- helpers -----

// normalizeClaimsSet ensures maps are non-nil so later lookups are safe.
func normalizeClaimsSet(cs jsonClaimsSet) jsonClaimsSet {
	if cs.ByPurpose == nil {
		cs.ByPurpose = make(map[string]jsonClaims)
	}
	normalizeLayer := func(l *jsonClaims) {
		if l.Base == nil {
			l.Base = make(map[string]interface{})
		}
		if l.ClientOverrides == nil {
			l.ClientOverrides = make(map[string]map[string]interface{})
		}
		if l.ScopeOverrides == nil {
			l.ScopeOverrides = make(map[string]map[string]interface{})
		}
	}
	normalizeLayer(&cs.Default)
	for k, v := range cs.ByPurpose {
		normalizeLayer(&v)
		cs.ByPurpose[k] = v
	}
	return cs
}

func applyLayer(dst map[string]interface{}, src map[string]interface{}) {
	for k, v := range src {
		dst[k] = v
	}
}
