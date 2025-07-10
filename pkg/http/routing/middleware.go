package routing

import (
	"context"
	"net/http"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/service/authentication"
	"github.com/axent-pl/oauth2mock/pkg/service/template"
	"github.com/axent-pl/oauth2mock/pkg/sessionservice"
	"github.com/axent-pl/oauth2mock/pkg/tpl"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

func RateLimitMiddleware(rps float64, burst int) Middleware {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)

	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}
			next(w, r)
		}
	}
}

func SessionMiddleware(sessionSrv sessionservice.SessionService) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			const (
				cookieSID string        = "sid"
				cookieTTL time.Duration = 60 * time.Second
			)
			var (
				sessionID   string
				sessionData sessionservice.SessionData
				ok          bool
			)

			cookie, err := r.Cookie(cookieSID)
			if err == nil {
				sessionID = cookie.Value
				_, ok = sessionSrv.Get(sessionID)
			}
			if !ok {
				sessionID = uuid.New().String()
				sessionData = sessionservice.SessionData{}
				sessionSrv.Put(sessionID, sessionData)

				http.SetCookie(w, &http.Cookie{
					Name:     cookieSID,
					Value:    sessionID,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
					MaxAge:   int(cookieTTL.Seconds()),
				})
			}

			ctx := context.WithValue(r.Context(), CTX_SESSION_ID, sessionID)
			next(w, r.WithContext(ctx))
		}
	}
}

func UserAuthenticationMiddleware(templateSrv template.TemplateServicer, userSrv userservice.UserServicer, sessionSrv sessionservice.SessionService) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			templateData := tpl.AuthorizeTemplateData{
				FormAction: r.URL.String(),
			}

			valid := true

			// session
			sessionID, ok := r.Context().Value(CTX_SESSION_ID).(string)
			if !ok {
				http.Error(w, "user session not initialized", http.StatusInternalServerError)
				return
			}
			sessionData, ok := sessionSrv.Get(sessionID)
			if !ok {
				http.Error(w, "user session not initialized", http.StatusInternalServerError)
				return
			}
			if userRaw, ok := sessionData["user"]; ok {
				user, casted := userRaw.(userservice.UserHandler)
				if !casted {
					http.Error(w, "could not fetch user from session", http.StatusInternalServerError)
					return
				}
				ctx := context.WithValue(r.Context(), CTX_USER, user)
				r = r.WithContext(ctx)
				next(w, r)
				return
			}

			// form validation
			username := r.PostFormValue("username")
			if username == "" {
				templateData.UsernameError = "username is required"
				valid = false
			}
			password := r.PostFormValue("password")
			if password == "" {
				templateData.PasswordError = "password is required"
				valid = false
			}
			if !valid {
				templateData.FormErrorMessage = "invalid credentials"
				templateData.Username = username
				templateSrv.Render(w, "login", templateData)
				return
			}

			// credentials initialization
			credentials, err := authentication.NewCredentials(authentication.FromUsernameAndPassword(username, password))
			if err != nil {
				templateData.FormErrorMessage = "invalid credentials"
				templateData.Username = username
				templateSrv.Render(w, "login", templateData)
				return
			}

			// authentication
			user, err := userSrv.Authenticate(credentials)
			if err != nil {
				templateData.FormErrorMessage = "invalid credentials"
				templateData.Username = username
				templateSrv.Render(w, "login", templateData)
				return
			}

			ctx := context.WithValue(r.Context(), CTX_USER, user)
			r = r.WithContext(ctx)
			sessionData["user"] = user
			sessionSrv.Put(sessionID, sessionData)
			next(w, r)
		}
	}
}
