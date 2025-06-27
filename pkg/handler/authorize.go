package handler

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/dto"
	"github.com/axent-pl/oauth2mock/pkg/http/request"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
	"github.com/axent-pl/oauth2mock/pkg/service/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/service/template"
	"github.com/axent-pl/oauth2mock/pkg/service/userservice"
	"github.com/axent-pl/oauth2mock/pkg/tpl"
)

func AuthorizeGetHandler(templateDB template.TemplateServicer, clientDB clientservice.ClientServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authorization request DTO
		authorizeRequestDTO := &dto.AuthorizeRequestDTO{}
		if valid, validator := request.UnmarshalAndValidate(r, authorizeRequestDTO); !valid {
			slog.Error("invalid authorize request", "validationErrors", validator.Errors)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// client
		client, err := clientDB.GetClient(authorizeRequestDTO.ClientId)
		if err != nil {
			slog.Error("invalid client", "error", err)
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
			slog.Error("invalid authorize request", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Init template data
		templateData := tpl.AuthorizeTemplateData{
			FormAction:           r.URL.String(),
			AuthorizationRequest: &authorizationRequest,
		}

		templateDB.Render(w, "login", templateData)
	}
}

func AuthorizePostHandler(templateDB template.TemplateServicer, clientDB clientservice.ClientServicer, userService userservice.UserServicer, authCodeDB auth.AuthorizationCodeServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authorization request DTO
		authorizeRequestDTO := &dto.AuthorizeRequestDTO{}
		if valid, validator := request.UnmarshalAndValidate(r, authorizeRequestDTO); !valid {
			slog.Error("invalid authorize request", "validationErrors", validator.Errors)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// client
		client, err := clientDB.GetClient(authorizeRequestDTO.ClientId)
		if err != nil {
			slog.Error("invalid client", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// authorization request
		authorizationRequest := auth.AuthorizationRequest{
			ResponseType: authorizeRequestDTO.ResponseType,
			RedirectURI:  authorizeRequestDTO.RedirectURI,
			Scope:        strings.Split(authorizeRequestDTO.Scope, " "),
			State:        authorizeRequestDTO.State,
			Nonce:        authorizeRequestDTO.Nonce,
			Client:       client,
		}
		err = authorizationRequest.Valid()
		if err != nil {
			slog.Error("invalid authorize request", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// authorization request credentials DTO
		authenticationErrorMessage := ""
		credentialsDTO := &dto.AuthorizeCredentialsDTO{}
		credentialsDTOValid, credentialsValidator := request.UnmarshalAndValidate(r, credentialsDTO)

		if credentialsDTOValid {
			credentials, err := authentication.NewCredentials(authentication.FromUsernameAndPassword(credentialsDTO.Username, credentialsDTO.Password))
			if err != nil {
				slog.Error("invalid authorize request credentials", "error", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// authentication
			user, authenticationErr := userService.Authenticate(credentials)
			if authenticationErr == nil {
				authorizationRequest.Subject = user
				code, err := authCodeDB.GenerateCode(&authorizationRequest, time.Hour)
				if err != nil {
					slog.Error("AuthorizePostHandler authorization code generation failed", "RequestID", r.Context().Value("RequestID"), "error", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				redirectURL, _ := url.Parse(authorizationRequest.RedirectURI)
				redirectURLQuery := redirectURL.Query()
				redirectURLQuery.Add("code", code)
				redirectURLQuery.Add("state", authorizationRequest.State)
				redirectURL.RawQuery = redirectURLQuery.Encode()
				slog.Info("AuthorizePostHandler redirecting", "RequestID", r.Context().Value("RequestID"), "redirectURL", redirectURL.String())
				http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
			} else {
				authenticationErrorMessage = authenticationErr.Error()
				slog.Error("AuthorizePostHandler authentication failed", "RequestID", r.Context().Value("RequestID"), "error", authenticationErr)
			}
		}

		// Init template data
		templateData := tpl.AuthorizeTemplateData{
			FormAction:           r.URL.String(),
			ValidationErrors:     credentialsValidator.Errors,
			AuthenticationError:  authenticationErrorMessage,
			Credentials:          *credentialsDTO,
			AuthorizationRequest: &authorizationRequest,
		}

		templateDB.Render(w, "login", templateData)
	}
}
