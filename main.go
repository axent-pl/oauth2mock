package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"text/template"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/jwk"
	"github.com/axent-pl/oauth2mock/pkg/token"
)

const loginTemplateFile = "tpl/login.go.tpl"

func main() {
	key := jwk.MustLoadOrGenerate()
	authCodeDB := auth.NewAuthorizationCodeInMemoryStore()
	clientDB := auth.NewClientSimpleStore()
	subjectDB := auth.NewSubjectSimpleStorer()

	http.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("DONE"))
	})

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks, _ := key.GetJWKS()
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// authorization request DTO
		authorizeRequestDTO := &AuthorizeRequestDTO{}
		Hydrate(authorizeRequestDTO, r)
		authorizeRequestValidator := NewValidator()
		if !authorizeRequestValidator.Validate(authorizeRequestDTO) {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// client
		client, err := clientDB.GetClient(authorizeRequestDTO.ClientId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// authorization request
		authorizationRequest := auth.AuthorizationRequest{
			ResponseType: authorizeRequestDTO.ResponseType,
			RedirectURI:  authorizeRequestDTO.RedirectURI,
			Scope:        authorizeRequestDTO.Scope,
			State:        authorizeRequestDTO.State,
			Client:       client,
		}
		err = authorizationRequest.Valid()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// credentials
		credentialsDTO := &AuthorizeCredentialsDTO{}
		credentialsValidator := NewValidator()
		if r.Method == http.MethodPost {
			err := r.ParseMultipartForm(32 << 20)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			Hydrate(credentialsDTO, r)
			if credentialsValidator.Validate(credentialsDTO) {
				credentials := auth.Credentials{
					Username: credentialsDTO.Username,
					Password: credentialsDTO.Password,
				}
				// authentication
				subject, authenticationErr := subjectDB.Authenticate(credentials)
				if authenticationErr == nil {
					authorizationRequest.Subject = subject
					code, err := authCodeDB.GenerateCode(&authorizationRequest, time.Hour)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					redirectURL, _ := url.Parse(authorizationRequest.RedirectURI)
					redirectURLQuery := redirectURL.Query()
					redirectURLQuery.Add("code", code)
					redirectURL.RawQuery = redirectURLQuery.Encode()

					http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
				}
			}
		}

		// Init template data
		templateData := struct {
			FormAction           string
			ValidationErrors     map[string]ValidationError
			Credentials          AuthorizeCredentialsDTO
			AuthorizationRequest *auth.AuthorizationRequest
		}{
			FormAction:           r.URL.String(),
			ValidationErrors:     credentialsValidator.Errors,
			Credentials:          *credentialsDTO,
			AuthorizationRequest: &authorizationRequest,
		}

		templateCodeBytes, err := os.ReadFile(loginTemplateFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl, err := template.New("login").Parse(string(templateCodeBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, templateData)
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// client_id
		// client_secret
		// client_assertion_type
		// client_assertion
		// code
		// redirect_uri
		// grant_type

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		err := r.ParseMultipartForm(32 << 20)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !r.PostForm.Has("grant_type") {
			http.Error(w, "missing grant_type", http.StatusBadRequest)
			return
		}

		tokenResponse, err := token.GetTokenResponse("username1", "clientA", key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(tokenResponse)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
