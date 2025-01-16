package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/axent-pl/oauth2mock/auth"
	"github.com/axent-pl/oauth2mock/dto"
	"github.com/axent-pl/oauth2mock/routing"
)

func TokenAuthorizationCodeHandler(openidConfig auth.OpenIDConfiguration, clientDB auth.ClientServicer, authCodeDB auth.AuthorizationCodeService, claimsDB auth.ClaimServicer, key *auth.JWK) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requstDTO := &dto.AuthorizationCodeTokenRequestDTO{}
		requestValidator := dto.NewValidator()
		dto.Unmarshal(r, requstDTO)
		if !requestValidator.Validate(requstDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if requstDTO.GrantType != "authorization_code" {
			http.Error(w, "invalid grant type", http.StatusBadRequest)
			return
		}

		// Authenticate client
		credentials, err := auth.NewAuthenticationCredentials(auth.FromCliendIdAndSecret(requstDTO.ClientId, requstDTO.ClientSecret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		client, err := clientDB.Authenticate(credentials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Get authorization request data
		authCodeData, ok := authCodeDB.GetCode(requstDTO.Code)
		if !ok {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}

		// Validate request DTO with authCodeData
		if requstDTO.ClientId != authCodeData.Request.Client.Id {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}
		if requstDTO.RedirectURI != authCodeData.Request.RedirectURI {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}

		subject := authCodeData.Request.Subject
		scope := authCodeData.Request.Scope
		claims, err := claimsDB.GetClaims(subject, *client, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		issuer := openidConfig.Issuer
		if openidConfig.UseOrigin {
			issuer = getOriginFromRequest(r)
		}

		tokenResponse, err := auth.NewTokenReponse(issuer, subject, *client, claims, *key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tokenResponseBytes, err := json.Marshal(tokenResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(tokenResponseBytes)
	}
}

func TokenClientCredentialsHandler(openidConfig auth.OpenIDConfiguration, clientDB auth.ClientServicer, claimsDB auth.ClaimServicer, key *auth.JWK) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requstDTO := &dto.ClientCredentialsTokenRequestDTO{}
		requestValidator := dto.NewValidator()
		dto.Unmarshal(r, requstDTO)
		if !requestValidator.Validate(requstDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if requstDTO.GrantType != "client_credentials" {
			http.Error(w, "invalid grant type", http.StatusBadRequest)
			return
		}

		// Authenticate client
		credentials, err := auth.NewAuthenticationCredentials(auth.FromCliendIdAndSecret(requstDTO.ClientId, requstDTO.ClientSecret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		client, err := clientDB.Authenticate(credentials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		scope := make([]string, 0)
		if len(requstDTO.Scope) > 0 {
			scope = strings.Split(requstDTO.Scope, " ")
		}
		claims, err := claimsDB.GetClaims(client, *client, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		issuer := openidConfig.Issuer
		if openidConfig.UseOrigin {
			issuer = getOriginFromRequest(r)
		}

		tokenResponse, err := auth.NewTokenReponse(issuer, client, *client, claims, *key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tokenResponseBytes, err := json.Marshal(tokenResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(tokenResponseBytes)
	}
}
