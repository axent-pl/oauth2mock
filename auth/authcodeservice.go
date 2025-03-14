package auth

import (
	"sync"
	"time"
)

// AuthorizationCodeService defines the interface for an authorization code database
type AuthorizationCodeService interface {
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

// AuthorizationCodeSimpleService is a thread-safe store for authorization codes
type AuthorizationCodeSimpleService struct {
	codes   map[string]AuthorizationCodeData
	codesMU sync.RWMutex
}

// NewAuthorizationCodeSimpleService creates a new instance of AuthorizationCodeDatabase
func NewAuthorizationCodeSimpleService() (*AuthorizationCodeSimpleService, error) {
	db := &AuthorizationCodeSimpleService{
		codes: make(map[string]AuthorizationCodeData),
	}
	go db.cleanupExpiredCodes() // Background task to clean up expired codes
	return db, nil
}

// GenerateCode generates and stores an authorization code with a TTL
func (db *AuthorizationCodeSimpleService) GenerateCode(request *AuthorizationRequest, ttl time.Duration) (string, error) {
	db.codesMU.Lock()
	defer db.codesMU.Unlock()

	// Generate code
	code, err := GenerateRandomCode(32)
	if err != nil {
		return "", err
	}

	// Save AuthorizationRequest data
	codeData := AuthorizationCodeData{
		code:      code,
		expiresAt: time.Now().Add(ttl),
		Request:   request,
	}

	db.codes[code] = codeData

	return code, nil
}

// GetCode retrieves an authorization code if it exists and has not expired
func (db *AuthorizationCodeSimpleService) GetCode(code string) (AuthorizationCodeData, bool) {
	db.codesMU.RLock()
	defer db.codesMU.RUnlock()

	data, exists := db.codes[code]
	if !exists || time.Now().After(data.expiresAt) {
		return AuthorizationCodeData{}, false
	}

	delete(db.codes, code)

	return data, true
}

// RevokeCode removes an authorization code from the database
func (db *AuthorizationCodeSimpleService) RevokeCode(code string) {
	db.codesMU.Lock()
	defer db.codesMU.Unlock()
	delete(db.codes, code)
}

// cleanupExpiredCodes removes expired authorization codes periodically
func (db *AuthorizationCodeSimpleService) cleanupExpiredCodes() {
	ticker := time.NewTicker(1 * time.Minute) // Adjust interval as needed
	defer ticker.Stop()

	for range ticker.C {
		db.codesMU.Lock()
		for code, data := range db.codes {
			if time.Now().After(data.expiresAt) {
				delete(db.codes, code)
			}
		}
		db.codesMU.Unlock()
	}
}
