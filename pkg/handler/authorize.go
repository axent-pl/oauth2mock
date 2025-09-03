package handler

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/axent-pl/oauth2mock/pkg/authorizationservice"
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/consentservice"
	"github.com/axent-pl/oauth2mock/pkg/di"
	"github.com/axent-pl/oauth2mock/pkg/dto"
	"github.com/axent-pl/oauth2mock/pkg/errs"
	"github.com/axent-pl/oauth2mock/pkg/http/request"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/template"
	"github.com/axent-pl/oauth2mock/pkg/tpl"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

func AuthorizeResponseTypeCodeHandler() routing.HandlerFunc {
	var wired bool
	var templateSrv template.Service
	var clientSrv clientservice.Service
	var authZSrv authorizationservice.Service
	var consentSrv consentservice.Service

	templateSrv, wired = di.GiveMeInterface(templateSrv)
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
	consentSrv, wired = di.GiveMeInterface(consentSrv)
	if !wired {
		slog.Error("could not wire consent service")
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
			templateSrv.Render(w, "login", templateData)
			return
		}

		// client
		client, err := clientSrv.GetClient(authorizeRequestDTO.ClientId)
		if err != nil {
			routing.WriteError(w, r, errs.Wrap("invalid client_id", err).WithKind(errs.ErrInvalidArgument))
			return
		}

		// user
		user, ok := r.Context().Value(routing.CTX_USER).(userservice.Entity)
		if !ok {
			routing.WriteError(w, r, errs.New("unauthenticated", errs.ErrUnauthenticated).WithDetails("user not found in contextr"))
			return
		}

		// validate scopes
		scopes := strings.Split(authorizeRequestDTO.Scope, " ")
		consents, err := consentSrv.GetConsents(user, client, scopes)
		if err != nil {
			routing.WriteError(w, r, err)
			return
		}
		templateData.Consents = consents

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
			routing.WriteError(w, r, err)
			return
		}
		if err := authZSrv.Validate(authorizationRequest); err != nil {
			routing.WriteError(w, r, err)
			return
		}

		// authorization request response
		code, err := authZSrv.Store(authorizationRequest)
		if err != nil {
			routing.WriteError(w, r, err)
			return
		}
		redirectURL, err := url.Parse(authorizationRequest.GetRedirectURI())
		if err != nil {
			routing.WriteError(w, r, err)
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
