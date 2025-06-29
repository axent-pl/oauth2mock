package claimservice

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/service/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/service/userservice"
)

type claimDetails struct {
	Base            map[string]interface{}
	ClientOverrides map[string]map[string]interface{}
	ScopeOverrides  map[string]map[string]interface{}
}

type claimService struct {
	claimsJSONFilepath string // Path to the claims JSON file.
	userClaims         map[string]claimDetails
	clientClaims       map[string]claimDetails
	claimsMU           sync.RWMutex // Mutex to synchronize access to claims.
	lastModified       time.Time    // Tracks the last modification time of the file.
}

func NewClaimService(claimsJSONFilepath string) (ClaimServicer, error) {
	file, err := os.Open(claimsJSONFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open claims config file: %w", err)
	}
	defer file.Close()

	userClaims, clientClaims, err := unmarshalClaimsFromReader(file)
	if err != nil {
		return nil, err
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	cs := &claimService{
		userClaims:         userClaims,
		clientClaims:       clientClaims,
		claimsJSONFilepath: claimsJSONFilepath,
		lastModified:       fileInfo.ModTime(),
	}

	return cs, nil
}

func (s *claimService) GetUserClaims(user userservice.UserHandler, client clientservice.ClientHandler, scope []string) (map[string]interface{}, error) {
	s.claimsMU.RLock()
	defer s.claimsMU.RUnlock()

	claims := make(map[string]interface{})

	userClaims, err := readUserClaims(user)
	if err != nil {
		return claims, err
	}

	// Add base claims.
	for c, v := range userClaims.Base {
		claims[c] = v
	}

	// Override claims with client-specific values, if available.
	clientOverrides, ok := userClaims.ClientOverrides[client.Id()]
	if ok {
		for c, v := range clientOverrides {
			claims[c] = v
		}
	}

	for _, scopeItem := range scope {
		scopeOverrides, ok := userClaims.ScopeOverrides[scopeItem]
		if ok {
			for c, v := range scopeOverrides {
				claims[c] = v
			}
		}
	}

	return claims, nil
}

// GetClaims retrieves claims for a given user and client.
func (s *claimService) GetClientClaims(client clientservice.ClientHandler, scope []string) (map[string]interface{}, error) {
	s.claimsMU.RLock()
	defer s.claimsMU.RUnlock()

	claims := make(map[string]interface{})

	clientClaims, ok := s.clientClaims[client.Name()]
	if !ok {
		return claims, fmt.Errorf("no claims for client %s", client.Name())
	}

	// Add base claims.
	for c, v := range clientClaims.Base {
		claims[c] = v
	}

	// Override claims with client-specific values, if available.
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

func readUserClaims(user userservice.UserHandler) (claimDetails, error) {
	claims := claimDetails{
		Base:            make(map[string]interface{}),
		ClientOverrides: make(map[string]map[string]interface{}),
		ScopeOverrides:  make(map[string]map[string]interface{}),
	}

	userClaims := user.GetAttributesGroup("claims")
	if userClaims == nil {
		return claims, fmt.Errorf("no claims for user %s", user.Name())
	}

	if userBase, ok := userClaims["base"]; ok {
		claims.Base = userBase.(map[string]interface{})
	}
	if userClientOverrides, ok := userClaims["clientOverrides"]; ok {
		for clientId, clientOverrides := range userClientOverrides.(map[string]interface{}) {
			claims.ClientOverrides[clientId] = clientOverrides.(map[string]interface{})
		}
	}
	if userScopeOverrides, ok := userClaims["scopeOverrides"]; ok {
		for scope, scopeOverrides := range userScopeOverrides.(map[string]interface{}) {
			claims.ScopeOverrides[scope] = scopeOverrides.(map[string]interface{})
		}
	}

	return claims, nil
}

func unmarshalClaimsFromReader(reader io.Reader) (map[string]claimDetails, map[string]claimDetails, error) {
	var rawData struct {
		UsersWrapper struct {
			Users map[string]struct {
				Claims struct {
					Base            map[string]interface{}            `json:"base"`
					ClientOverrides map[string]map[string]interface{} `json:"clientOverrides"`
					ScopeOverrides  map[string]map[string]interface{} `json:"scopeOverrides"`
				} `json:"claims"`
			} `json:"users"`
		} `json:"users"`
		Clients map[string]struct {
			Claims struct {
				Base            map[string]interface{}            `json:"base"`
				ClientOverrides map[string]map[string]interface{} `json:"clientOverrides"`
				ScopeOverrides  map[string]map[string]interface{} `json:"scopeOverrides"`
			} `json:"claims"`
		} `json:"clients"`
	}

	if err := json.NewDecoder(reader).Decode(&rawData); err != nil {
		return nil, nil, fmt.Errorf("failed to parse claims config file: %w", err)
	}

	userClaims := make(map[string]claimDetails)
	for username, user := range rawData.UsersWrapper.Users {
		userClaims[username] = claimDetails{
			Base:            user.Claims.Base,
			ClientOverrides: user.Claims.ClientOverrides,
			ScopeOverrides:  user.Claims.ScopeOverrides,
		}
	}
	clientClaims := make(map[string]claimDetails)
	for clientId, client := range rawData.Clients {
		clientClaims[clientId] = claimDetails{
			Base:            client.Claims.Base,
			ClientOverrides: client.Claims.ClientOverrides,
			ScopeOverrides:  client.Claims.ScopeOverrides,
		}
	}

	return userClaims, clientClaims, nil
}
