package token

import (
	"fmt"
	"net/http"
)

func getOriginFromRequest(r *http.Request) string {
	hostWithPort := r.Host
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, hostWithPort)
}
