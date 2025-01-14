package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/axent-pl/oauth2mock/auth"
	"github.com/axent-pl/oauth2mock/dto"
	"github.com/axent-pl/oauth2mock/routing"
	"github.com/axent-pl/oauth2mock/template"
)

func JWKSGetHandler(key *auth.JWK) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks, _ := key.GetJWKS()
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	}
}

func WellKnownHandler(openidConfig auth.OpenIDConfiguration) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		openidConfigCopy := openidConfig
		hostWithPort := r.Host
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		origin := fmt.Sprintf("%s://%s", scheme, hostWithPort)
		openidConfigCopy.SetIssuer(origin)
		resp, err := json.Marshal(openidConfigCopy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)

	}
}

func AuthorizeGetHandler(templateDB template.TemplateStorer, clientDB auth.ClientStorer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authorization request DTO
		authorizeRequestDTO := &dto.AuthorizeRequestDTO{}
		authorizeRequestValidator := dto.NewValidator()
		dto.Unmarshal(r, authorizeRequestDTO)
		if !authorizeRequestValidator.Validate(authorizeRequestDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// client
		client, err := clientDB.GetClient(authorizeRequestDTO.ClientId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// authorization request
		authorizationRequest := auth.AuthorizationRequest{
			ResponseType: authorizeRequestDTO.ResponseType,
			RedirectURI:  authorizeRequestDTO.RedirectURI,
			Scope:        authorizeRequestDTO.Scope,
			State:        authorizeRequestDTO.State,
			Client:       client,
		}
		err = authorizationRequest.Valid()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Init template data
		templateData := template.AuthorizeTemplateData{
			FormAction:           r.URL.String(),
			AuthorizationRequest: &authorizationRequest,
		}

		templateDB.Render(w, "login", templateData)
	}
}

func AuthorizePostHandler(templateDB template.TemplateStorer, clientDB auth.ClientStorer, subjectDB auth.SubjectServicer, authCodeDB auth.AuthorizationCodeStorer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authorization request DTO
		authorizeRequestDTO := &dto.AuthorizeRequestDTO{}
		authorizeRequestValidator := dto.NewValidator()
		dto.Unmarshal(r, authorizeRequestDTO)
		slog.Info("AuthorizePostHandler reading authorize request param done", "RequestID", r.Context().Value("RequestID"), "authorizeRequestDTO", authorizeRequestDTO)

		if !authorizeRequestValidator.Validate(authorizeRequestDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			slog.Error("AuthorizePostHandler validating authorize request param failed", "RequestID", r.Context().Value("RequestID"), "validationErrors", authorizeRequestValidator.Errors)
			return
		}

		// client
		client, err := clientDB.GetClient(authorizeRequestDTO.ClientId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("AuthorizePostHandler fetching client failed", "RequestID", r.Context().Value("RequestID"), "clientID", authorizeRequestDTO.ClientId, "error", err)
			return
		}

		// authorization request
		authorizationRequest := auth.AuthorizationRequest{
			ResponseType: authorizeRequestDTO.ResponseType,
			RedirectURI:  authorizeRequestDTO.RedirectURI,
			Scope:        authorizeRequestDTO.Scope,
			State:        authorizeRequestDTO.State,
			Client:       client,
		}
		err = authorizationRequest.Valid()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			slog.Error("AuthorizePostHandler validating authorize request failed", "RequestID", r.Context().Value("RequestID"), "error", err)
			return
		}

		// credentials
		authenticationErrorMessage := ""
		credentialsDTO := &dto.AuthorizeCredentialsDTO{}
		credentialsValidator := dto.NewValidator()
		dto.Unmarshal(r, credentialsDTO)
		slog.Info("AuthorizePostHandler subject credentials", "RequestID", r.Context().Value("RequestID"), "credentialsDTO", credentialsDTO)
		if credentialsValidator.Validate(credentialsDTO) {
			credentials, err := auth.NewAuthenticationCredentials(auth.FromUsernameAndPassword(credentialsDTO.Username, credentialsDTO.Password))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				slog.Error("AuthorizePostHandler subject credentials initialization failed", "RequestID", r.Context().Value("RequestID"), "error", err)
				return
			}
			// authentication
			subject, authenticationErr := subjectDB.Authenticate(credentials)
			if authenticationErr == nil {
				authorizationRequest.Subject = subject
				code, err := authCodeDB.GenerateCode(&authorizationRequest, time.Hour)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					slog.Error("AuthorizePostHandler authorization code generation failed", "RequestID", r.Context().Value("RequestID"), "error", err)
					return
				}
				redirectURL, _ := url.Parse(authorizationRequest.RedirectURI)
				redirectURLQuery := redirectURL.Query()
				redirectURLQuery.Add("code", code)
				redirectURL.RawQuery = redirectURLQuery.Encode()
				slog.Info("AuthorizePostHandler redirecting", "RequestID", r.Context().Value("RequestID"), "redirectURL", redirectURL.String())
				http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
			} else {
				authenticationErrorMessage = authenticationErr.Error()
				slog.Error("AuthorizePostHandler authentication failed", "RequestID", r.Context().Value("RequestID"), "error", authenticationErr)
			}
		}

		// Init template data
		templateData := template.AuthorizeTemplateData{
			FormAction:           r.URL.String(),
			ValidationErrors:     credentialsValidator.Errors,
			AuthenticationError:  authenticationErrorMessage,
			Credentials:          *credentialsDTO,
			AuthorizationRequest: &authorizationRequest,
		}

		templateDB.Render(w, "login", templateData)
	}
}

func TokenAuthorizationCodeHandler(clientDB auth.ClientStorer, authCodeDB auth.AuthorizationCodeStorer, claimsDB auth.ClaimServicer, key *auth.JWK) routing.HandlerFunc {
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
		scope := make([]string, 0)
		claims, err := claimsDB.GetClaims(subject, *client, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		tokenResponse, err := auth.NewTokenReponse(subject, *client, claims, *key)
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
