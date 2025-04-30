package handler

import (
	"net/http"

	"github.com/axent-pl/oauth2mock/auth"
	routing "github.com/axent-pl/oauth2mock/pkg/http/router"
)

func JWKSGetHandler(key *auth.JWK) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks, _ := key.GetJWKS()
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	}
}
