package auth

import (
	"time"

	"github.com/axent-pl/oauth2mock/pkg/service/signing"
	"github.com/axent-pl/oauth2mock/pkg/service/userservice"
)

type TokenResponse struct {
	Type         string `json:"type"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
}

func getSubClaim(user userservice.UserHandler, client ClientHandler) string {
	if user != nil {
		return user.Id()
	}
	return client.Id()
}

func NewTokenReponse(issuer string, user userservice.UserHandler, client ClientHandler, claims map[string]interface{}, keyService signing.SigningServicer) (TokenResponse, error) {
	tokenResponse := TokenResponse{Type: "Bearer"}

	access_token_claims := make(map[string]interface{})
	access_token_claims["iss"] = issuer
	access_token_claims["sub"] = getSubClaim(user, client)
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
	refresh_token_claims["sub"] = getSubClaim(user, client)
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

	id_token_claims := make(map[string]interface{})
	id_token_claims["iss"] = issuer
	id_token_claims["sub"] = getSubClaim(user, client)
	id_token_claims["aud"] = client.Id()
	id_token_claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	id_token_claims["iat"] = time.Now().Unix()
	id_token_claims["typ"] = "ID"
	for k, v := range claims {
		id_token_claims[k] = v
	}
	id_token, err := keyService.Sign(id_token_claims)
	if err != nil {
		return TokenResponse{}, err
	}
	tokenResponse.IDToken = string(id_token)

	return tokenResponse, nil
}
