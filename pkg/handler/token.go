package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/authorizationservice"
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

func subClaim(user userservice.Entity, client clientservice.Entity) string {
	if user != nil {
		return user.Id()
	}
	return client.Id()
}

func userOrClientClaims(claimSvc claimservice.Service, user userservice.Entity, client clientservice.Entity, scopes []string, purpose string) (map[string]interface{}, error) {
	if user != nil {
		return claimSvc.GetUserClaims(user, client, scopes, purpose)
	}
	return claimSvc.GetClientClaims(client, scopes, purpose)
}

func tokenReponse(issuer string, user userservice.Entity, client clientservice.Entity, scopes []string, extraClaims map[string]interface{}, claimSvc claimservice.Service, keyService signing.SigningServicer) (dto.TokenResponseDTO, error) {
	tokenResponse := dto.TokenResponseDTO{TokenType: "Bearer", Expires: 3600}

	// access token
	access_claims, err := userOrClientClaims(claimSvc, user, client, scopes, "access")
	if err != nil {
		return dto.TokenResponseDTO{}, err
	}
	access_token_claims := make(map[string]interface{})
	access_token_claims["iss"] = issuer
	access_token_claims["sub"] = subClaim(user, client)
	access_token_claims["azp"] = client.Id()
	access_token_claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	access_token_claims["iat"] = time.Now().Unix()
	access_token_claims["typ"] = "Bearer"
	for k, v := range access_claims {
		access_token_claims[k] = v
	}
	for k, v := range extraClaims {
		access_token_claims[k] = v
	}
	access_token, err := keyService.Sign(access_token_claims)
	if err != nil {
		return dto.TokenResponseDTO{}, err
	}
	tokenResponse.AccessToken = string(access_token)

	// refresh token
	refresh_claims, err := userOrClientClaims(claimSvc, user, client, scopes, "refresh")
	if err != nil {
		return dto.TokenResponseDTO{}, err
	}
	refresh_token_claims := make(map[string]interface{})
	refresh_token_claims["iss"] = issuer
	refresh_token_claims["sub"] = subClaim(user, client)
	refresh_token_claims["azp"] = client.Id()
	refresh_token_claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	refresh_token_claims["iat"] = time.Now().Unix()
	refresh_token_claims["typ"] = "Refresh"
	for k, v := range refresh_claims {
		refresh_token_claims[k] = v
	}
	for k, v := range extraClaims {
		refresh_token_claims[k] = v
	}
	refresh_token, err := keyService.Sign(refresh_token_claims)
	if err != nil {
		return dto.TokenResponseDTO{}, err
	}
	tokenResponse.RefreshToken = string(refresh_token)

	// refresh token
	id_claims, err := userOrClientClaims(claimSvc, user, client, scopes, "id")
	if err != nil {
		return dto.TokenResponseDTO{}, err
	}
	id_token_claims := make(map[string]interface{})
	id_token_claims["iss"] = issuer
	id_token_claims["sub"] = subClaim(user, client)
	id_token_claims["aud"] = client.Id()
	id_token_claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	id_token_claims["iat"] = time.Now().Unix()
	id_token_claims["typ"] = "ID"
	for k, v := range id_claims {
		id_token_claims[k] = v
	}
	for k, v := range extraClaims {
		id_token_claims[k] = v
	}
	id_token, err := keyService.Sign(id_token_claims)
	if err != nil {
		return dto.TokenResponseDTO{}, err
	}
	tokenResponse.IDToken = string(id_token)

	return tokenResponse, nil
}

func TokenAuthorizationCodeHandler(openidConfig auth.OpenIDConfiguration, clientSvc clientservice.Service, consentSvc consentservice.Service, authCodeSvc authorizationservice.Service, claimSvc claimservice.Service, keySvc signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler TokenAuthorizationCodeHandler started", "request", routing.RequestIDLogValue(r))
		requstDTO := &dto.TokenAuthorizationCodeRequestDTO{}
		requestValidator := request.NewValidator()
		request.Unmarshal(r, requstDTO)
		if !requestValidator.Validate(requstDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			slog.Error("request validation failed", "request", routing.RequestIDLogValue(r), "validationErrors", requestValidator.Errors)
			return
		}
		if requstDTO.GrantType != "authorization_code" {
			http.Error(w, "invalid grant type", http.StatusBadRequest)
			slog.Error("invalid grant type", "request", routing.RequestIDLogValue(r))
			return
		}

		// Authenticate client
		credentials, err := authentication.NewCredentials(authentication.FromCliendIdAndSecret(requstDTO.ClientId, requstDTO.ClientSecret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("could not read client credentials", "request", routing.RequestIDLogValue(r), "ClientId", requstDTO.ClientId, "error", err)
			return
		}
		client, err := clientSvc.Authenticate(credentials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("invalid client credentials", "request", routing.RequestIDLogValue(r), "ClientId", requstDTO.ClientId, "error", err)
			return
		}

		// Get authorization request data
		authorizationRequest, err := authCodeSvc.Get(requstDTO.Code)
		if err != nil {
			http.Error(w, "invalid code", http.StatusBadRequest)
			slog.Error("invalid authorization code", "request", routing.RequestIDLogValue(r), "ClientId", requstDTO.Code, "error", err)
			return
		}

		// Validate request DTO with authCodeData
		if requstDTO.ClientId != authorizationRequest.GetClient().Id() {
			http.Error(w, "invalid code", http.StatusBadRequest)
			slog.Error("authorization code client does not match", "request", routing.RequestIDLogValue(r), "ClientId", requstDTO.Code)
			return
		}
		if requstDTO.RedirectURI != authorizationRequest.GetRedirectURI() {
			http.Error(w, "invalid code", http.StatusBadRequest)
			slog.Error("authorization code redirect URI does not match", "request", routing.RequestIDLogValue(r), "ClientId", requstDTO.Code)
			return
		}

		subject := authorizationRequest.GetUser()
		scopes := authorizationRequest.GetScopes()

		extraClaims := make(map[string]interface{})
		if authorizationRequest.GetNonce() != "" {
			extraClaims["nonce"] = authorizationRequest.GetNonce()
		}

		issuer := openidConfig.Issuer
		if openidConfig.UseOrigin {
			issuer = getOriginFromRequest(r)
		}

		tokenResponse, err := tokenReponse(issuer, subject, client, scopes, extraClaims, claimSvc, keySvc)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("failed to construct token response", "request", routing.RequestIDLogValue(r), "error", err)
			return
		}
		tokenResponseBytes, err := json.Marshal(tokenResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("failed to marshal token response", "request", routing.RequestIDLogValue(r), "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Write(tokenResponseBytes)

		slog.Info("token response successful", "request", routing.RequestIDLogValue(r))
	}
}

func TokenClientCredentialsHandler(openidConfig auth.OpenIDConfiguration, clientDB clientservice.Service, claimsDB claimservice.Service, keyService signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler TokenClientCredentialsHandler started", "request", routing.RequestIDLogValue(r))
		requstDTO := &dto.TokenClientCredentialsHandlerRequestDTO{}
		requestValidator := request.NewValidator()
		request.Unmarshal(r, requstDTO)
		if !requestValidator.Validate(requstDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			slog.Error("request validation failed", "request", routing.RequestIDLogValue(r), "validationErrors", requestValidator.Errors)
			return
		}
		if requstDTO.GrantType != "client_credentials" {
			http.Error(w, "invalid grant type", http.StatusBadRequest)
			slog.Error("invalid grant type", "request", routing.RequestIDLogValue(r))
			return
		}

		// Authenticate client
		credentials, err := authentication.NewCredentials(authentication.FromCliendIdAndSecret(requstDTO.ClientId, requstDTO.ClientSecret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("could not read client credentials", "request", routing.RequestIDLogValue(r), "ClientId", requstDTO.ClientId, "error", err)
			return
		}
		client, err := clientDB.Authenticate(credentials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("invalid client credentials", "request", routing.RequestIDLogValue(r), "ClientId", requstDTO.ClientId, "error", err)
			return
		}

		scope := make([]string, 0)
		if len(requstDTO.Scope) > 0 {
			scope = strings.Split(requstDTO.Scope, " ")
		}
		issuer := openidConfig.Issuer
		if openidConfig.UseOrigin {
			issuer = getOriginFromRequest(r)
		}
		extraClaims := make(map[string]interface{})
		tokenResponse, err := tokenReponse(issuer, nil, client, scope, extraClaims, claimsDB, keyService)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("failed to construct token response", "request", routing.RequestIDLogValue(r), "error", err)
			return
		}
		tokenResponseBytes, err := json.Marshal(tokenResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("failed to marshal token response", "request", routing.RequestIDLogValue(r), "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Write(tokenResponseBytes)

		slog.Info("token response successful", "request", routing.RequestIDLogValue(r))
	}
}

func TokenPasswordHandler(openidConfig auth.OpenIDConfiguration, clientSvc clientservice.Service, userSvc userservice.Service, claimSvc claimservice.Service, consentSvc consentservice.Service, keySvc signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler TokenPasswordHandler started")
		requstDTO := &dto.TokenPasswrodRequestDTO{}
		requestValidator := request.NewValidator()
		request.Unmarshal(r, requstDTO)
		if !requestValidator.Validate(requstDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			slog.Error("request validation failed", "request", routing.RequestIDLogValue(r), "validationErrors", requestValidator.Errors)
			return
		}
		if requstDTO.GrantType != "password" {
			http.Error(w, "invalid grant type", http.StatusBadRequest)
			slog.Error("invalid grant type", "request", routing.RequestIDLogValue(r))
			return
		}

		// Authenticate client
		clientCredentials, err := authentication.NewCredentials(authentication.FromCliendIdAndSecret(requstDTO.ClientId, requstDTO.ClientSecret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("could not read client credentials", "request", routing.RequestIDLogValue(r), "ClientId", requstDTO.ClientId, "error", err)
			return
		}
		client, err := clientSvc.Authenticate(clientCredentials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("invalid client credentials", "request", routing.RequestIDLogValue(r), "ClientId", requstDTO.ClientId, "error", err)
			return
		}

		// Authenticate user
		userCredenmtials, err := authentication.NewCredentials(authentication.FromUsernameAndPassword(requstDTO.Username, requstDTO.Password))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("could not read user credentials", "request", routing.RequestIDLogValue(r), "Username", requstDTO.Username, "error", err)
			return
		}
		user, err := userSvc.Authenticate(userCredenmtials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("invalid client credentials", "request", routing.RequestIDLogValue(r), "Username", requstDTO.Username, "error", err)
			return
		}

		scope := make([]string, 0)
		if len(requstDTO.Scope) > 0 {
			scope = strings.Split(requstDTO.Scope, " ")
		}

		issuer := openidConfig.Issuer
		if openidConfig.UseOrigin {
			issuer = getOriginFromRequest(r)
		}
		extraClaims := make(map[string]interface{})
		tokenResponse, err := tokenReponse(issuer, user, client, scope, extraClaims, claimSvc, keySvc)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("failed to construct token response", "request", routing.RequestIDLogValue(r), "error", err)
			return
		}
		tokenResponseBytes, err := json.Marshal(tokenResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("failed to marshal token response", "request", routing.RequestIDLogValue(r), "error", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Write(tokenResponseBytes)

		slog.Info("token response successful", "request", routing.RequestIDLogValue(r))
	}
}
