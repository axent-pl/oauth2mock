package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"text/template"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/jwk"
	"github.com/axent-pl/oauth2mock/server"
)

func JWKSGetHandler(key *jwk.JWK) server.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks, _ := key.GetJWKS()
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	}
}

func AuthorizeGetHandler(clientDB auth.ClientStorer) server.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authorization request DTO
		authorizeRequestDTO := &AuthorizeRequestDTO{}
		authorizeRequestValidator := NewValidator()
		Hydrate(authorizeRequestDTO, r)
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
		templateData := struct {
			FormAction           string
			ValidationErrors     map[string]ValidationError
			AuthenticationError  string
			Credentials          AuthorizeCredentialsDTO
			AuthorizationRequest *auth.AuthorizationRequest
		}{
			FormAction:           r.URL.String(),
			AuthorizationRequest: &authorizationRequest,
		}

		templateCodeBytes, err := os.ReadFile(loginTemplateFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl, err := template.New("login").Parse(string(templateCodeBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, templateData)
	}
}

func AuthorizePostHandler(clientDB auth.ClientStorer, subjectDB auth.SubjectStorerInterface, authCodeDB auth.AuthorizationCodeStorer) server.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authorization request DTO
		authorizeRequestDTO := &AuthorizeRequestDTO{}
		authorizeRequestValidator := NewValidator()
		Hydrate(authorizeRequestDTO, r)
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

		// credentials
		authenticationErrorMessage := ""
		credentialsDTO := &AuthorizeCredentialsDTO{}
		credentialsValidator := NewValidator()
		Hydrate(credentialsDTO, r)

		if credentialsValidator.Validate(credentialsDTO) {
			credentials, err := auth.NewCredentials(auth.WithUsernameAndPassword(credentialsDTO.Username, credentialsDTO.Password))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// authentication
			subject, authenticationErr := subjectDB.Authenticate(*credentials)
			if authenticationErr == nil {
				authorizationRequest.Subject = subject
				code, err := authCodeDB.GenerateCode(&authorizationRequest, time.Hour)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				redirectURL, _ := url.Parse(authorizationRequest.RedirectURI)
				redirectURLQuery := redirectURL.Query()
				redirectURLQuery.Add("code", code)
				redirectURL.RawQuery = redirectURLQuery.Encode()

				http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
			} else {
				authenticationErrorMessage = authenticationErr.Error()
			}
		}

		// Init template data
		templateData := struct {
			FormAction           string
			ValidationErrors     map[string]ValidationError
			AuthenticationError  string
			Credentials          AuthorizeCredentialsDTO
			AuthorizationRequest *auth.AuthorizationRequest
		}{
			FormAction:           r.URL.String(),
			ValidationErrors:     credentialsValidator.Errors,
			AuthenticationError:  authenticationErrorMessage,
			Credentials:          *credentialsDTO,
			AuthorizationRequest: &authorizationRequest,
		}

		templateCodeBytes, err := os.ReadFile(loginTemplateFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl, err := template.New("login").Parse(string(templateCodeBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, templateData)
	}
}

func TokenAuthorizationCodeHandler(clientDB auth.ClientStorer, authCodeDB auth.AuthorizationCodeStorer, claimsDB auth.ClaimStorer, key *jwk.JWK) server.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requstDTO := &AuthorizationCodeTokenRequestDTO{}
		requestValidator := NewValidator()
		Hydrate(requstDTO, r)
		if !requestValidator.Validate(requstDTO) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if requstDTO.GrantType != "authorization_code" {
			http.Error(w, "invalid grant type", http.StatusBadRequest)
			return
		}

		// Authenticate client
		credentials := auth.Credentials{
			ClientId:     requstDTO.ClientId,
			ClientSecret: requstDTO.ClientSecret,
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
		claims, err := claimsDB.GetClaims(*subject, *client)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		tokenResponse, err := auth.NewTokenReponse(*subject, *client, claims, *key)
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
