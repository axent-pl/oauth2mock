package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/claimservice"
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/consentservice"
	"github.com/axent-pl/oauth2mock/pkg/dto"
	"github.com/axent-pl/oauth2mock/pkg/http/request"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

func TokenAuthorizationCodeHandler(openidConfig auth.OpenIDConfiguration, clientSvc clientservice.ClientServicer, consentSvc consentservice.ConsentServicer, authCodeSvc auth.AuthorizationCodeServicer, claimSvc claimservice.ClaimServicer, keySvc signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler TokenAuthorizationCodeHandler started")
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
		client, err := clientSvc.Authenticate(credentials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Get authorization request data
		authCodeData, ok := authCodeSvc.GetCode(requstDTO.Code)
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
		claims, err := claimSvc.GetUserClaims(subject, client, consentSvc, scope)
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

		tokenResponse, err := auth.NewTokenReponse(issuer, subject, client, claims, keySvc)
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
		slog.Info("request handler TokenClientCredentialsHandler started")
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

func TokenPasswordHandler(openidConfig auth.OpenIDConfiguration, clientSvc clientservice.ClientServicer, userSvc userservice.UserServicer, claimSvc claimservice.ClaimServicer, consentSvc consentservice.ConsentServicer, keySvc signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler TokenPasswordHandler started")
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
		client, err := clientSvc.Authenticate(clientCredentials)
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
		user, err := userSvc.Authenticate(userCredenmtials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		scope := make([]string, 0)
		if len(requstDTO.Scope) > 0 {
			scope = strings.Split(requstDTO.Scope, " ")
		}
		claims, err := claimSvc.GetUserClaims(user, client, consentSvc, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		issuer := openidConfig.Issuer
		if openidConfig.UseOrigin {
			issuer = getOriginFromRequest(r)
		}

		tokenResponse, err := auth.NewTokenReponse(issuer, user, client, claims, keySvc)
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
