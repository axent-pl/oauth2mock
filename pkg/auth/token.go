package auth

import "github.com/axent-pl/oauth2mock/pkg/jwk"

type TokenResponse struct {
	Type         string `json:"type"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

func NewTokenReponse(subject Subject, client Client, claims map[string]interface{}, key jwk.JWK) (TokenResponse, error) {
	tokenResponse := TokenResponse{Type: "Bearer"}

	access_token_claims := make(map[string]interface{})
	access_token_claims["iss"] = "https://todo.issuer.uri"
	access_token_claims["sub"] = subject.Name
	access_token_claims["aud"] = client.Id
	access_token_claims["typ"] = "Bearer"
	for k, v := range claims {
		access_token_claims[k] = v
	}
	access_token, err := key.SignJWT(access_token_claims)
	if err != nil {
		return TokenResponse{}, err
	}
	tokenResponse.AccessToken = string(access_token)

	refresh_token_claims := make(map[string]interface{})
	refresh_token_claims["sub"] = subject.Name
	refresh_token_claims["aud"] = client.Id
	refresh_token_claims["typ"] = "Refresh"
	for k, v := range claims {
		refresh_token_claims[k] = v
	}
	refresh_token, err := key.SignJWT(refresh_token_claims)
	if err != nil {
		return TokenResponse{}, err
	}
	tokenResponse.RefreshToken = string(refresh_token)

	return tokenResponse, nil
}
