package auth

import "time"

// AuthorizationCodeStorer defines the interface for an authorization code database
type AuthorizationCodeStorer interface {
	// GenerateCode generates and stores an authorization code with a TTL
	GenerateCode(request *AuthorizationRequest, ttl time.Duration) (string, error)

	// GetCode retrieves an authorization code if it exists and has not expired
	GetCode(code string) (AuthorizationCodeData, bool)

	// RevokeCode removes an authorization code from the database
	RevokeCode(code string)
}
