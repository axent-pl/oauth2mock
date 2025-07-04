package handler

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/authorizationservice"
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/dto"
	"github.com/axent-pl/oauth2mock/pkg/http/request"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
	"github.com/axent-pl/oauth2mock/pkg/service/template"
	"github.com/axent-pl/oauth2mock/pkg/tpl"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

func AuthorizeGetHandler(templateDB template.TemplateServicer, clientDB clientservice.ClientServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler AuthorizeGetHandler started")
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
			FormAction: r.URL.String(),
		}

		templateDB.Render(w, "login", templateData)
	}
}

func AuthorizePostHandler(templateDB template.TemplateServicer, clientSrv clientservice.ClientServicer, userSrv userservice.UserServicer, authZSrv authorizationservice.AuthorizationServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler AuthorizePostHandler started")

		templateData := tpl.AuthorizeTemplateData{
			FormAction: r.URL.String(),
		}

		// authorization request DTO
		authorizeRequestDTO := &dto.AuthorizeRequestDTO{}
		if valid, validator := request.UnmarshalAndValidate(r, authorizeRequestDTO); !valid {
			slog.Error("invalid authorize request", "validationErrors", validator.Errors)
			templateData.FormErrorMessage = "invalid authorize request"
			templateDB.Render(w, "login", templateData)
			return
		}

		// client
		client, err := clientSrv.GetClient(authorizeRequestDTO.ClientId)
		if err != nil {
			slog.Error("invalid client", "error", err)
			templateData.FormErrorMessage = "invalid client"
			templateDB.Render(w, "login", templateData)
			return
		}

		// user
		credentialsDTO := &dto.AuthorizeCredentialsDTO{}
		if valid, validator := request.UnmarshalAndValidate(r, credentialsDTO); !valid {
			slog.Error("invalid authorize request user credentials", "validationErrors", validator.Errors)
			templateData.FormErrorMessage = "invalid credentials"
			templateData.Username = credentialsDTO.Username
			templateData.PasswordError = validator.Errors["password"].ErrorMessage
			templateData.UsernameError = validator.Errors["username"].ErrorMessage
			templateDB.Render(w, "login", templateData)
			return
		}
		credentials, err := authentication.NewCredentials(authentication.FromUsernameAndPassword(credentialsDTO.Username, credentialsDTO.Password))
		if err != nil {
			slog.Error("invalid authorize request credentials", "error", err)
			templateData.FormErrorMessage = "invalid credentials"
			templateData.Username = credentialsDTO.Username
			templateDB.Render(w, "login", templateData)
			return
		}
		user, err := userSrv.Authenticate(credentials)
		if err != nil {
			slog.Error("invalid authorize request credentials", "error", err)
			templateData.FormErrorMessage = "invalid credentials"
			templateData.Username = credentialsDTO.Username
			templateDB.Render(w, "login", templateData)
			return
		}

		// authorization request
		authorizationRequest, err := authorizationservice.NewAuthorizationRequest(
			authorizeRequestDTO.ResponseType,
			strings.Split(authorizeRequestDTO.Scope, " "),
			client,
			authorizationservice.WithRedirectURI(authorizeRequestDTO.RedirectURI),
			authorizationservice.WithState(authorizeRequestDTO.State),
			authorizationservice.WithNonce(authorizeRequestDTO.Nonce),
			authorizationservice.WithUser(user))
		if err != nil {
			slog.Error("invalid authorize request", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if authZSrv.Validate(authorizationRequest); err != nil {
			slog.Error("invalid authorize request", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// authorization request response
		code, err := authZSrv.Store(authorizationRequest)
		if err != nil {
			slog.Error("AuthorizePostHandler authorization code generation failed", "RequestID", r.Context().Value("RequestID"), "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		redirectURL, _ := url.Parse(authorizationRequest.GetRedirectURI())
		redirectURLQuery := redirectURL.Query()
		redirectURLQuery.Add("code", code)
		redirectURLQuery.Add("state", authorizationRequest.GetState())
		redirectURL.RawQuery = redirectURLQuery.Encode()
		slog.Info("AuthorizePostHandler redirecting", "RequestID", r.Context().Value("RequestID"), "redirectURL", redirectURL.String())
		http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
	}
}
