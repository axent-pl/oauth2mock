package authentication

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 16
	iterations = 100_000
	keyLength  = 32
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha256.New)

	// Store salt + hash as base64
	fullHash := append(salt, hash...)
	return base64.StdEncoding.EncodeToString(fullHash), nil
}

func CheckPasswordHash(password, encodedHash string) (bool, error) {
	fullHash, err := base64.StdEncoding.DecodeString(encodedHash)
	if err != nil || len(fullHash) < saltSize {
		return false, fmt.Errorf("invalid encoded hash")
	}

	salt := fullHash[:saltSize]
	expectedHash := fullHash[saltSize:]

	computedHash := pbkdf2.Key([]byte(password), salt, iterations, len(expectedHash), sha256.New)

	// Constant-time comparison
	if len(expectedHash) != len(computedHash) {
		return false, nil
	}
	result := byte(0)
	for i := 0; i < len(expectedHash); i++ {
		result |= expectedHash[i] ^ computedHash[i]
	}
	return result == 0, nil
}
