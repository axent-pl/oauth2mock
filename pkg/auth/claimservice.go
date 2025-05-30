package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

// ClaimServicer interface defines a method to retrieve claims for a subject and client.
type ClaimServicer interface {
	GetUserClaims(user UserHandler, client ClientHandler, scope []string) (map[string]interface{}, error)
	GetClientClaims(client ClientHandler, scope []string) (map[string]interface{}, error)
}

// claimDetails holds the base claims and client-specific overrides.
type claimDetails struct {
	Base            map[string]interface{}
	ClientOverrides map[string]map[string]interface{}
	ScopeOverrides  map[string]map[string]interface{}
}

// claimService implements the ClaimServicer interface and manages claim data.
type claimService struct {
	claimsJSONFilepath string // Path to the claims JSON file.
	userClaims         map[string]claimDetails
	clientClaims       map[string]claimDetails
	claimsMU           sync.RWMutex // Mutex to synchronize access to claims.
	lastModified       time.Time    // Tracks the last modification time of the file.
}

// NewClaimService initializes the claim service by loading claims from the provided file path.
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
	go cs.reloadClaimsJob()
	return cs, nil
}

// unmarshalClaimsFromReader reads and parses the JSON file into claim details.
func unmarshalClaimsFromReader(reader io.Reader) (map[string]claimDetails, map[string]claimDetails, error) {
	var rawData struct {
		Users map[string]struct {
			Claims struct {
				Base            map[string]interface{}            `json:"base"`
				ClientOverrides map[string]map[string]interface{} `json:"clientOverrides"`
				ScopeOverrides  map[string]map[string]interface{} `json:"scopeOverrides"`
			} `json:"claims"`
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
	for username, user := range rawData.Users {
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

// reloadClaimsJob periodically checks and reloads the claims file if it has changed.
func (s *claimService) reloadClaimsJob() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.reloadClaims()
	}
}

// reloadClaims reloads claims from the file only if the file has been modified.
func (s *claimService) reloadClaims() {
	s.claimsMU.Lock()
	defer s.claimsMU.Unlock()

	fileInfo, err := os.Stat(s.claimsJSONFilepath)
	if err != nil {
		slog.Error("failed to stat claims config file", "error", err)
		return
	}

	// Check if the file has been modified since the last reload.
	if !fileInfo.ModTime().After(s.lastModified) {
		return
	}

	slog.Info("reloading claims from claims config file")

	file, err := os.Open(s.claimsJSONFilepath)
	if err != nil {
		slog.Error("failed to open claims config file", "error", err)
		return
	}
	defer file.Close()

	userClaims, clientClaims, err := unmarshalClaimsFromReader(file)
	if err != nil {
		slog.Error("failed to parse claims config file", "error", err)
		return
	}

	// Update claims and last modification time.
	s.userClaims = userClaims
	s.clientClaims = clientClaims
	s.lastModified = fileInfo.ModTime()
}

// GetClaims retrieves claims for a given user and client.
func (s *claimService) GetUserClaims(subject UserHandler, client ClientHandler, scope []string) (map[string]interface{}, error) {
	s.claimsMU.RLock()
	defer s.claimsMU.RUnlock()

	claims := make(map[string]interface{})

	userClaims, ok := s.userClaims[subject.Name()]
	if !ok {
		return claims, fmt.Errorf("no claims for subject %s", subject.Name())
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
func (s *claimService) GetClientClaims(client ClientHandler, scope []string) (map[string]interface{}, error) {
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
