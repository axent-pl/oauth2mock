package handler

import (
	"log/slog"
	"net/http"

	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
)

func JWKSGetHandler(keyService signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request handler JWKSGetHandler started")
		jwksResponse, _ := keyService.GetJWKS()
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksResponse)
	}
}
