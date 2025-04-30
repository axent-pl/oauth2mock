package handler

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/axent-pl/oauth2mock/auth"
	"github.com/axent-pl/oauth2mock/dto"
	routing "github.com/axent-pl/oauth2mock/pkg/http/router"
	"github.com/axent-pl/oauth2mock/template"
)

func AuthorizeGetHandler(templateDB template.TemplateStorer, clientDB auth.ClientServicer) routing.HandlerFunc {
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
			Scope:        strings.Split(authorizeRequestDTO.Scope, " "),
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

func AuthorizePostHandler(templateDB template.TemplateStorer, clientDB auth.ClientServicer, subjectDB auth.UserServicer, authCodeDB auth.AuthorizationCodeService) routing.HandlerFunc {
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
			Scope:        strings.Split(authorizeRequestDTO.Scope, " "),
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
