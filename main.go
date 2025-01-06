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

	http.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("DONE"))
	})

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks, _ := key.GetJWKS()
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Get client
		client, err := clientDB.GetClient(r.URL.Query().Get("client_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Get subject
		subject := auth.Subject{
			Credentials: auth.Credentials{
				Username: "",
				Password: "",
			},
		}
		if r.Method == http.MethodPost {
			err := r.ParseMultipartForm(32 << 20)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			subject.Credentials.Username = r.PostFormValue("username")
			subject.Credentials.Password = r.PostFormValue("password")
		}

		// Get authorizationRequest
		authorizationRequest := auth.AuthorizationRequest{
			ResponseType: r.URL.Query().Get("response_type"),
			RedirectURI:  r.URL.Query().Get("redirect_uri"),
			Scope:        r.URL.Query().Get("scope"),
			State:        r.URL.Query().Get("state"),
			Client:       client,
			Subject:      &subject,
		}

		// Validate authorizationRequest
		err = authorizationRequest.Valid()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Init template data
		templateData := struct {
			FormValid            bool
			FormAction           string
			ValidationMessage    string
			AuthorizationRequest *auth.AuthorizationRequest
		}{
			FormValid:            true,
			FormAction:           r.URL.String(),
			ValidationMessage:    "",
			AuthorizationRequest: &authorizationRequest,
		}

		if r.Method == http.MethodPost {
			// Validate Subject Credentials
			err = authorizationRequest.Subject.Credentials.Valid()

			if err != nil {
				templateData.FormValid = false
				templateData.ValidationMessage = err.Error()
			} else {
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
