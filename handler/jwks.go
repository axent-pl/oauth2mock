package handler

import (
	"net/http"

	routing "github.com/axent-pl/oauth2mock/pkg/http/router"
	"github.com/axent-pl/oauth2mock/pkg/service/key"
)

func JWKSGetHandler(keyService key.JWKServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks, _ := keyService.GetJWKS()
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	}
}
