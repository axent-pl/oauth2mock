package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/axent-pl/oauth2mock/auth"
	"github.com/axent-pl/oauth2mock/routing"
)

func WellKnownHandler(openidConfig auth.OpenIDConfiguration) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		openidConfigCopy := openidConfig
		hostWithPort := r.Host
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		origin := fmt.Sprintf("%s://%s", scheme, hostWithPort)
		openidConfigCopy.SetIssuer(origin)
		resp, err := json.Marshal(openidConfigCopy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)

	}
}
