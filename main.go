package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/jwk"
	"github.com/axent-pl/oauth2mock/routing"
	"github.com/axent-pl/oauth2mock/server"
	"github.com/axent-pl/oauth2mock/template"
)

var (
	serverAddress string

	authCodeStore auth.AuthorizationCodeStorer
	clientStore   auth.ClientStorer
	subjectStore  auth.SubjectStorerInterface
	claimStore    auth.ClaimStorer
	templateStore template.TemplateStorer

	key        jwk.JWK
	router     routing.Router
	httpServer server.Server
)

// Configure logger
func init() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	jsonLogger := slog.New(jsonHandler)
	slog.SetDefault(jsonLogger)
}

// Configure stores
func init() {
	authCodeStore = auth.NewAuthorizationCodeInMemoryStore()
	clientStore = auth.NewClientSimpleStore("run/users.json")
	subjectStore = auth.NewSubjectSimpleStorer()
	claimStore = auth.NewClaimSimpleStorer("run/users.json")
	templateStore = template.MustNewDefaultTemplateStore("tpl")
}

// JWK
func init() {
	key = jwk.MustLoadOrGenerate()
}

// Configure HTTP router and server
func init() {
	serverAddress = ":8080"

	router = routing.Router{}
	router.RegisterHandler(JWKSGetHandler(&key), routing.WithMethod(http.MethodGet), routing.WithPath("/.well-known/jwks.json"))
	router.RegisterHandler(AuthorizeGetHandler(templateStore, clientStore), routing.WithMethod(http.MethodGet), routing.WithPath("/authorize"), routing.ForQueryValue("response_type", "code"))
	router.RegisterHandler(AuthorizePostHandler(templateStore, clientStore, subjectStore, authCodeStore), routing.WithMethod(http.MethodPost), routing.WithPath("/authorize"), routing.ForQueryValue("response_type", "code"))
	router.RegisterHandler(TokenAuthorizationCodeHandler(clientStore, authCodeStore, claimStore, &key), routing.WithMethod(http.MethodPost), routing.WithPath("/token"), routing.ForPostFormValue("grant_type", "authorization_code"))

	httpServer = server.Server{
		Addr:   serverAddress,
		Router: router,
	}
}

func main() {
	fmt.Println(templateStore)

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGABRT)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signalChannel
		cancel()
	}()
	defer cancel()

	if err := httpServer.Start(ctx); err != nil {
		os.Exit(1)
	}
}
