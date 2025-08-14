package handler

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/axent-pl/oauth2mock/pkg/authorizationservice"
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/di"
	"github.com/axent-pl/oauth2mock/pkg/dto"
	"github.com/axent-pl/oauth2mock/pkg/http/request"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/template"
	"github.com/axent-pl/oauth2mock/pkg/tpl"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

func AuthorizeResponseTypeCodeHandler() routing.HandlerFunc {
	var wired bool
	var templateDB template.Service
	var clientSrv clientservice.Service
	var authZSrv authorizationservice.Service

	templateDB, wired = di.GiveMeInterface(templateDB)
	if !wired {
		slog.Error("could not wire template service")
		return nil
	}
	clientSrv, wired = di.GiveMeInterface(clientSrv)
	if !wired {
		slog.Error("could not wire client service")
		return nil
	}
	authZSrv, wired = di.GiveMeInterface(authZSrv)
	if !wired {
		slog.Error("could not wire authorization service")
		return nil
	}

	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler AuthorizePostHandler started", "request", routing.RequestIDLogValue(r))

		templateData := tpl.AuthorizeTemplateData{
			FormAction: r.URL.String(),
		}

		// authorization request DTO
		authorizeRequestDTO := &dto.AuthorizeRequestDTO{}
		if valid, validator := request.UnmarshalAndValidate(r, authorizeRequestDTO); !valid {
			slog.Error("invalid authorize request", "request", routing.RequestIDLogValue(r), "validationErrors", validator.Errors)
			templateData.FormErrorMessage = "invalid authorize request"
			templateDB.Render(w, "login", templateData)
			return
		}

		// client
		client, err := clientSrv.GetClient(authorizeRequestDTO.ClientId)
		if err != nil {
			slog.Error("invalid client", "request", routing.RequestIDLogValue(r), "error", err)
			templateData.FormErrorMessage = "invalid client"
			templateDB.Render(w, "login", templateData)
			return
		}

		// user
		user, ok := r.Context().Value(routing.CTX_USER).(userservice.Entity)
		if !ok {
			http.Error(w, "authentication failure", http.StatusInternalServerError)
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
			slog.Error("invalid authorize request", "request", routing.RequestIDLogValue(r), "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := authZSrv.Validate(authorizationRequest); err != nil {
			slog.Error("invalid authorize request", "request", routing.RequestIDLogValue(r), "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// authorization request response
		code, err := authZSrv.Store(authorizationRequest)
		if err != nil {
			slog.Error("AuthorizePostHandler authorization code generation failed", "request", routing.RequestIDLogValue(r), "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		redirectURL, err := url.Parse(authorizationRequest.GetRedirectURI())
		if err != nil {
			slog.Error("invalid redirect uel format", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		redirectURLQuery := redirectURL.Query()
		redirectURLQuery.Add("code", code)
		redirectURLQuery.Add("state", authorizationRequest.GetState())
		redirectURL.RawQuery = redirectURLQuery.Encode()
		slog.Info("AuthorizePostHandler redirecting", "request", routing.RequestIDLogValue(r), "redirectURL", redirectURL.String())
		http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
	}
}
