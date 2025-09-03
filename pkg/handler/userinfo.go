package handler

import (
	"net/http"

	"encoding/json"
	"strings"

	"github.com/axent-pl/oauth2mock/pkg/claimservice"
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/errs"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
	"github.com/golang-jwt/jwt/v5"
)

func UserinfoHandler(userSvc userservice.Service, clientSvc clientservice.Service, claimSvc claimservice.Service, keySvc signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			routing.WriteError(w, r, errs.New("missing authorization header", errs.ErrUnauthenticated))
			return
		}
		if !strings.HasPrefix(authHeader, "Bearer ") {
			routing.WriteError(w, r, errs.New("invalid authorization header", errs.ErrUnauthenticated).WithDetailsf("want 'Bearer ' got '%.10s...'", authHeader))
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if !keySvc.Valid([]byte(tokenString)) {
			routing.WriteError(w, r, errs.New("invalid token signature", errs.ErrUnauthenticated))
			return
		}
		// Parse token claims
		parsedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			routing.WriteError(w, r, errs.Wrap("invalid token", err).WithKind(errs.ErrUnauthenticated))
			return
		}
		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			routing.WriteError(w, r, errs.New("invalid token", errs.ErrUnauthenticated).WithDetails("could not extract claims from token"))
			return
		}

		// extract user
		userId, ok := claims["sub"].(string)
		if !ok {
			routing.WriteError(w, r, errs.New("invalid token", errs.ErrUnauthenticated).WithDetails("missing 'sub' claim"))
			return
		}
		user, err := userSvc.GetUser(userId)
		if err != nil {
			routing.WriteError(w, r, errs.Wrap("invalid token", err).WithKind(errs.ErrUnauthenticated))
			return
		}
		// extract client
		clientId, ok := claims["azp"].(string)
		if !ok {
			routing.WriteError(w, r, errs.New("invalid token", errs.ErrUnauthenticated).WithDetails("missing 'azp' claim"))
			return
		}
		client, err := clientSvc.GetClient(clientId)
		if err != nil {
			routing.WriteError(w, r, errs.Wrap("invalid token", err).WithKind(errs.ErrUnauthenticated))
			return
		}
		// extract scopes
		scopeStr, ok := claims["scope"].(string)
		if !ok {
			routing.WriteError(w, r, errs.New("invalid token", errs.ErrUnauthenticated).WithDetails("missing 'scope' claim"))
			return
		}
		scopes := strings.Fields(scopeStr)

		userinfo, err := claimSvc.GetUserClaims(user, client, scopes, "userinfo")
		if err != nil {
			routing.WriteError(w, r, errs.Wrap("internal server error", err).WithKind(errs.ErrInternal))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userinfo)
	}
}
