package wellknown

import (
	"encoding/json"
	"net/http"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
)

func WellKnownHandler(openidConfig auth.OpenIDConfiguration) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		openidConfigCopy := openidConfig

		if openidConfig.UseOrigin {
			origin := getOriginFromRequest(r)
			openidConfigCopy.SetIssuer(origin)
		}

		resp, err := json.Marshal(openidConfigCopy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)

	}
}
