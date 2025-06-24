package auth

import (
	"sync"
	"time"
)

// AuthorizationCodeServicer defines the interface for an authorization code database
type AuthorizationCodeServicer interface {
	// GenerateCode generates and stores an authorization code with a TTL
	GenerateCode(request *AuthorizationRequest, ttl time.Duration) (string, error)

	// GetCode retrieves an authorization code if it exists and has not expired
	GetCode(code string) (AuthorizationCodeData, bool)

	// RevokeCode removes an authorization code from the database
	RevokeCode(code string)
}

// AuthorizationCodeData represents the OAuth2 authorization code details
type AuthorizationCodeData struct {
	code      string
	expiresAt time.Time
	Request   *AuthorizationRequest
}

// AuthorizationCodeService is a thread-safe store for authorization codes
type AuthorizationCodeService struct {
	ticker     time.Duration
	codeLength int
	codes      map[string]AuthorizationCodeData
	codesMU    sync.RWMutex
}

// NewAuthorizationCodeService creates a new instance of AuthorizationCodeDatabase
func NewAuthorizationCodeService() (*AuthorizationCodeService, error) {
	db := &AuthorizationCodeService{
		ticker:     1 * time.Minute,
		codeLength: 32,
		codes:      make(map[string]AuthorizationCodeData),
	}
	go db.cleanupExpiredCodes() // Background task to clean up expired codes
	return db, nil
}

// GenerateCode generates and stores an authorization code with a TTL
func (acs *AuthorizationCodeService) GenerateCode(request *AuthorizationRequest, ttl time.Duration) (string, error) {
	acs.codesMU.Lock()
	defer acs.codesMU.Unlock()

	// Generate code
	code, err := GenerateRandomCode(acs.codeLength)
	if err != nil {
		return "", err
	}

	// Save AuthorizationRequest data
	codeData := AuthorizationCodeData{
		code:      code,
		expiresAt: time.Now().Add(ttl),
		Request:   request,
	}

	acs.codes[code] = codeData

	return code, nil
}

// GetCode retrieves an authorization code if it exists and has not expired
func (acs *AuthorizationCodeService) GetCode(code string) (AuthorizationCodeData, bool) {
	acs.codesMU.RLock()
	defer acs.codesMU.RUnlock()

	data, exists := acs.codes[code]
	if !exists || time.Now().After(data.expiresAt) {
		return AuthorizationCodeData{}, false
	}

	delete(acs.codes, code)

	return data, true
}

// RevokeCode removes an authorization code from the database
func (acs *AuthorizationCodeService) RevokeCode(code string) {
	acs.codesMU.Lock()
	defer acs.codesMU.Unlock()
	delete(acs.codes, code)
}

// cleanupExpiredCodes removes expired authorization codes periodically
func (acs *AuthorizationCodeService) cleanupExpiredCodes() {
	ticker := time.NewTicker(acs.ticker)
	defer ticker.Stop()

	for range ticker.C {
		acs.codesMU.Lock()
		for code, data := range acs.codes {
			if time.Now().After(data.expiresAt) {
				delete(acs.codes, code)
			}
		}
		acs.codesMU.Unlock()
	}
}
