package claimservice

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/consentservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type jsonClaimServiceConfig struct {
	UsersWrapper struct {
		Users map[string]struct {
			Username string     `json:"username"`
			Password string     `json:"password"`
			Claims   jsonClaims `json:"claims"`
		} `json:"users"`
	} `json:"users"`
	Clients map[string]struct {
		Claims jsonClaims `json:"claims"`
	} `json:"clients"`
}

type jsonClaims struct {
	Base            map[string]interface{}            `json:"base"`
	ClientOverrides map[string]map[string]interface{} `json:"clientOverrides"`
	ScopeOverrides  map[string]map[string]interface{} `json:"scopeOverrides"`
}

type jsonClaimService struct {
	userClaims     map[string]jsonClaims
	userClaimsMU   sync.RWMutex
	clientClaims   map[string]jsonClaims
	clientClaimsMU sync.RWMutex
}

func NewJSONClaimsService(rawClaimsConfig json.RawMessage, rawConfig json.RawMessage) (ClaimServicer, error) {
	slog.Info("claimservice factory NewJSONClaimsService started")
	config := jsonClaimServiceConfig{}
	service := jsonClaimService{
		userClaims:   make(map[string]jsonClaims),
		clientClaims: make(map[string]jsonClaims),
	}

	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, err
	}

	service.userClaimsMU.Lock()
	defer service.userClaimsMU.Unlock()
	for username, userData := range config.UsersWrapper.Users {
		service.userClaims[username] = userData.Claims
	}

	service.clientClaimsMU.Lock()
	defer service.clientClaimsMU.Unlock()
	for clientId, clientData := range config.Clients {
		service.clientClaims[clientId] = clientData.Claims
	}

	return &service, nil
}

func (s *jsonClaimService) GetClientClaims(client clientservice.ClientHandler, scope []string) (map[string]interface{}, error) {
	s.clientClaimsMU.RLock()
	defer s.clientClaimsMU.RUnlock()

	claims := make(map[string]interface{})

	clientClaims, ok := s.clientClaims[client.Name()]
	if !ok {
		return claims, fmt.Errorf("no claims for client %s", client.Name())
	}

	for c, v := range clientClaims.Base {
		claims[c] = v
	}

	clientOverrides, ok := clientClaims.ClientOverrides[client.Id()]
	if ok {
		for c, v := range clientOverrides {
			claims[c] = v
		}
	}

	for _, scopeItem := range scope {
		scopeOverrides, ok := clientClaims.ScopeOverrides[scopeItem]
		if ok {
			for c, v := range scopeOverrides {
				claims[c] = v
			}
		}
	}

	return claims, nil
}

func (s *jsonClaimService) GetUserClaims(user userservice.UserHandler, client clientservice.ClientHandler, consentService consentservice.ConsentServicer, scopes []string) (map[string]interface{}, error) {
	s.userClaimsMU.RLock()
	defer s.userClaimsMU.RUnlock()

	claims := make(map[string]interface{})
	consents, err := consentService.GetConsents(user, client, scopes)
	if err != nil {
		return nil, fmt.Errorf("could not get consents: %w", err)
	}

	userClaims, ok := s.userClaims[user.Id()]
	if !ok {
		return claims, fmt.Errorf("no claims for user %s", user.Name())
	}

	for c, v := range userClaims.Base {
		claims[c] = v
	}

	clientOverrides, ok := userClaims.ClientOverrides[client.Id()]
	if ok {
		for c, v := range clientOverrides {
			claims[c] = v
		}
	}

	grantedScopes := make([]string, 0)
	for _, scope := range scopes {
		scopeConsent, ok := consents[scope]
		if !ok {
			return nil, fmt.Errorf("undefined scope %s", scope)
		}
		scopeOverrides, ok := userClaims.ScopeOverrides[scope]
		if ok && scopeConsent.IsGranted() {
			grantedScopes = append(grantedScopes, scope)
			for c, v := range scopeOverrides {
				claims[c] = v
			}
		}
	}
	claims["scope"] = strings.Join(grantedScopes, " ")

	return claims, nil
}

func init() {
	Register("json", NewJSONClaimsService)
}
