package handler

import (
	"log/slog"
	"net/http"

	"encoding/json"
	"strings"

	"github.com/axent-pl/oauth2mock/pkg/claimservice"
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
	"github.com/golang-jwt/jwt/v5"
)

func UserinfoHandler(userSvc userservice.Service, clientSvc clientservice.Service, claimSvc claimservice.Service, keySvc signing.SigningServicer) routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if !keySvc.Valid([]byte(tokenString)) {
			http.Error(w, "Invalid token signature", http.StatusUnauthorized)
			return
		}
		// Parse token claims
		parsedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusUnauthorized)
			return
		}
		userId, _ := claims["sub"].(string)
		clientId, _ := claims["azp"].(string)
		scopeStr, _ := claims["scope"].(string)
		scopes := strings.Fields(scopeStr)
		var user userservice.Entity
		var client clientservice.Entity
		var errUser, errClient error
		if userId != "" {
			user, errUser = userSvc.GetUser(userId)
		}
		if clientId != "" {
			client, errClient = clientSvc.GetClient(clientId)
		}
		if errUser != nil && errClient != nil {
			http.Error(w, "User or client not found", http.StatusUnauthorized)
			return
		}
		var userinfo map[string]interface{}
		if user != nil {
			userinfo, err = claimSvc.GetUserClaims(user, client, scopes, "userinfo")
			slog.Debug("userinfo for user", "userinfo", userinfo, "userId", userId, "scope", scopes)
		} else {
			userinfo, err = claimSvc.GetClientClaims(client, scopes, "userinfo")
			slog.Debug("userinfo for client", "userinfo", userinfo, "clientId", clientId, "scope", scopes)
		}
		if err != nil {
			http.Error(w, "Failed to get claims", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userinfo)
	}
}
