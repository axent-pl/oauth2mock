package handler

import (
	"log/slog"
	"net/http"

	"github.com/axent-pl/oauth2mock/pkg/di"
	"github.com/axent-pl/oauth2mock/pkg/errs"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
)

func JWKSGetHandler() routing.HandlerFunc {
	var wired bool
	var keyService signing.SigningServicer
	keyService, wired = di.GiveMeInterface(keyService)
	if !wired {
		slog.Error("could not wire signing service")
		return nil
	}
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler JWKSGetHandler started")

		jwksResponse, err := keyService.GetJWKS()
		if err != nil {
			routing.WriteError(w, r, errs.Wrap("internal error", err).WithKind(errs.ErrInternal))
			return
		}

		if _, err := w.Write(jwksResponse); err != nil {
			routing.WriteError(w, r, errs.Wrap("internal error", err).WithKind(errs.ErrInternal))
			return
		}

		w.Header().Set("Content-Type", "application/json")
	}
}
