package authorizationservice

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

func GenerateRandomCode(length int) (string, error) {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	authCode := base64.RawURLEncoding.EncodeToString(randomBytes)

	if len(authCode) > length {
		authCode = authCode[:length]
	}

	return authCode, nil
}

func MatchesWildcard(redirectURI, clientRedirectURI string) bool {
	escapedPattern := regexp.QuoteMeta(clientRedirectURI)
	regexPattern := strings.ReplaceAll(escapedPattern, "\\*", ".*")
	regex, err := regexp.Compile("^" + regexPattern + "$")
	if err != nil {
		return false
	}
	return regex.MatchString(redirectURI)
}
