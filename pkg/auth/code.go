package auth

import (
	"sync"
	"time"
)

// AuthorizationCodeData represents the OAuth2 authorization code details
type AuthorizationCodeData struct {
	code      string
	expiresAt time.Time
	Request   *AuthorizationRequest
}

// AuthorizationCodeInMemoryStore is a thread-safe store for authorization codes
type AuthorizationCodeInMemoryStore struct {
	codes   map[string]AuthorizationCodeData
	codesMU sync.RWMutex
}

// NewAuthorizationCodeInMemoryStore creates a new instance of AuthorizationCodeDatabase
func NewAuthorizationCodeInMemoryStore() *AuthorizationCodeInMemoryStore {
	db := &AuthorizationCodeInMemoryStore{
		codes: make(map[string]AuthorizationCodeData),
	}
	go db.cleanupExpiredCodes() // Background task to clean up expired codes
	return db
}

// GenerateCode generates and stores an authorization code with a TTL
func (db *AuthorizationCodeInMemoryStore) GenerateCode(request *AuthorizationRequest, ttl time.Duration) (string, error) {
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
func (db *AuthorizationCodeInMemoryStore) GetCode(code string) (AuthorizationCodeData, bool) {
	db.codesMU.RLock()
	defer db.codesMU.RUnlock()

	data, exists := db.codes[code]
	if !exists || time.Now().After(data.expiresAt) {
		return AuthorizationCodeData{}, false
	}
	return data, true
}

// RevokeCode removes an authorization code from the database
func (db *AuthorizationCodeInMemoryStore) RevokeCode(code string) {
	db.codesMU.Lock()
	defer db.codesMU.Unlock()
	delete(db.codes, code)
}

// cleanupExpiredCodes removes expired authorization codes periodically
func (db *AuthorizationCodeInMemoryStore) cleanupExpiredCodes() {
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
