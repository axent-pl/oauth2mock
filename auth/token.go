package auth

import (
	"time"
)

type TokenResponse struct {
	Type         string `json:"type"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

func NewTokenReponse(issuer string, subject SubjectHandler, client ClientHandler, claims map[string]interface{}, key JWK) (TokenResponse, error) {
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
	access_token, err := key.SignJWT(access_token_claims, RS256)
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
	refresh_token, err := key.SignJWT(refresh_token_claims, RS256)
	if err != nil {
		return TokenResponse{}, err
	}
	tokenResponse.RefreshToken = string(refresh_token)

	return tokenResponse, nil
}
