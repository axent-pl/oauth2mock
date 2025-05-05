package handler

import (
	"net/http"

	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
)

func JWKSGetHandler(keyService signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks, _ := keyService.GetJWKS()
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	}
}
