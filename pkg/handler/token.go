package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/dto"
	"github.com/axent-pl/oauth2mock/pkg/http/request"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
	"github.com/axent-pl/oauth2mock/pkg/service/claimservice"
	"github.com/axent-pl/oauth2mock/pkg/service/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
	"github.com/axent-pl/oauth2mock/pkg/service/userservice"
)

func TokenAuthorizationCodeHandler(openidConfig auth.OpenIDConfiguration, clientDB clientservice.ClientServicer, authCodeDB auth.AuthorizationCodeServicer, claimsDB claimservice.ClaimServicer, keyService signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requstDTO := &dto.TokenAuthorizationCodeRequestDTO{}
		requestValidator := request.NewValidator()
		request.Unmarshal(r, requstDTO)
		if !requestValidator.Validate(requstDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if requstDTO.GrantType != "authorization_code" {
			http.Error(w, "invalid grant type", http.StatusBadRequest)
			return
		}

		// Authenticate client
		credentials, err := authentication.NewCredentials(authentication.FromCliendIdAndSecret(requstDTO.ClientId, requstDTO.ClientSecret))
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
		if requstDTO.ClientId != authCodeData.Request.Client.Id() {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}
		if requstDTO.RedirectURI != authCodeData.Request.RedirectURI {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}

		subject := authCodeData.Request.Subject
		scope := authCodeData.Request.Scope
		claims, err := claimsDB.GetUserClaims(subject, client, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if authCodeData.Request.Nonce != "" {
			claims["nonce"] = authCodeData.Request.Nonce
		}

		issuer := openidConfig.Issuer
		if openidConfig.UseOrigin {
			issuer = getOriginFromRequest(r)
		}

		tokenResponse, err := auth.NewTokenReponse(issuer, subject, client, claims, keyService)
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

func TokenClientCredentialsHandler(openidConfig auth.OpenIDConfiguration, clientDB clientservice.ClientServicer, claimsDB claimservice.ClaimServicer, keyService signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requstDTO := &dto.TokenClientCredentialsHandlerRequestDTO{}
		requestValidator := request.NewValidator()
		request.Unmarshal(r, requstDTO)
		if !requestValidator.Validate(requstDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if requstDTO.GrantType != "client_credentials" {
			http.Error(w, "invalid grant type", http.StatusBadRequest)
			return
		}

		// Authenticate client
		credentials, err := authentication.NewCredentials(authentication.FromCliendIdAndSecret(requstDTO.ClientId, requstDTO.ClientSecret))
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
		claims, err := claimsDB.GetClientClaims(client, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		issuer := openidConfig.Issuer
		if openidConfig.UseOrigin {
			issuer = getOriginFromRequest(r)
		}

		tokenResponse, err := auth.NewTokenReponse(issuer, nil, client, claims, keyService)
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

func TokenPasswordHandler(openidConfig auth.OpenIDConfiguration, clientDB clientservice.ClientServicer, userDB userservice.UserServicer, claimsDB claimservice.ClaimServicer, keyService signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requstDTO := &dto.TokenPasswrodRequestDTO{}
		requestValidator := request.NewValidator()
		request.Unmarshal(r, requstDTO)
		if !requestValidator.Validate(requstDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if requstDTO.GrantType != "password" {
			http.Error(w, "invalid grant type", http.StatusBadRequest)
			return
		}

		// Authenticate client
		clientCredentials, err := authentication.NewCredentials(authentication.FromCliendIdAndSecret(requstDTO.ClientId, requstDTO.ClientSecret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		client, err := clientDB.Authenticate(clientCredentials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Authenticate user
		userCredenmtials, err := authentication.NewCredentials(authentication.FromUsernameAndPassword(requstDTO.Username, requstDTO.Password))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, err := userDB.Authenticate(userCredenmtials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		scope := make([]string, 0)
		if len(requstDTO.Scope) > 0 {
			scope = strings.Split(requstDTO.Scope, " ")
		}
		claims, err := claimsDB.GetUserClaims(user, client, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		issuer := openidConfig.Issuer
		if openidConfig.UseOrigin {
			issuer = getOriginFromRequest(r)
		}

		tokenResponse, err := auth.NewTokenReponse(issuer, user, client, claims, keyService)
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
