package token

import (
	"encoding/json"

	"github.com/axent-pl/oauth2mock/pkg/claims"
	"github.com/axent-pl/oauth2mock/pkg/jwk"
)

type TokenResponse struct {
	Type         string `json:"type"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

func GetTokenResponse(subject string, client string, key jwk.JWK) ([]byte, error) {
	var tokenResponse = TokenResponse{Type: "Bearer"}

	// Accees Token
	access_token_claims, err := claims.GetClaims(subject, client)
	if err != nil {
		return nil, err
	}
	access_token_claims["iss"] = "https://todo.issuer.uri"
	access_token_claims["sub"] = subject
	access_token_claims["aud"] = client
	access_token_claims["typ"] = "Bearer"
	access_token, err := key.SignJWT(access_token_claims)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = string(access_token)

	// Refresh Token
	refresh_token_claims, err := claims.GetClaims(subject, client)
	if err != nil {
		return nil, err
	}
	refresh_token_claims["iss"] = "https://todo.issuer.uri"
	refresh_token_claims["sub"] = subject
	refresh_token_claims["aud"] = client
	refresh_token_claims["typ"] = "Refresh"
	refresh_token, err := key.SignJWT(refresh_token_claims)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = string(refresh_token)

	return json.Marshal(tokenResponse)
}
