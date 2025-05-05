package auth

import (
	"time"

	"github.com/axent-pl/oauth2mock/pkg/service/signing"
)

type TokenResponse struct {
	Type         string `json:"type"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

func NewTokenReponse(issuer string, subject SubjectHandler, client ClientHandler, claims map[string]interface{}, keyService signing.SigningServicer) (TokenResponse, error) {
	tokenResponse := TokenResponse{Type: "Bearer"}

	access_token_claims := make(map[string]interface{})
	access_token_claims["iss"] = issuer
	access_token_claims["sub"] = subject.Name()
	access_token_claims["azp"] = client.Id()
	access_token_claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	access_token_claims["iat"] = time.Now().Unix()
	access_token_claims["typ"] = "Bearer"
	for k, v := range claims {
		access_token_claims[k] = v
	}
	access_token, err := keyService.Sign(access_token_claims)
	if err != nil {
		return TokenResponse{}, err
	}
	tokenResponse.AccessToken = string(access_token)

	refresh_token_claims := make(map[string]interface{})
	refresh_token_claims["iss"] = issuer
	refresh_token_claims["sub"] = subject.Name()
	refresh_token_claims["azp"] = client.Id()
	refresh_token_claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	refresh_token_claims["iat"] = time.Now().Unix()
	refresh_token_claims["typ"] = "Refresh"
	for k, v := range claims {
		refresh_token_claims[k] = v
	}
	refresh_token, err := keyService.Sign(refresh_token_claims)
	if err != nil {
		return TokenResponse{}, err
	}
	tokenResponse.RefreshToken = string(refresh_token)

	return tokenResponse, nil
}
