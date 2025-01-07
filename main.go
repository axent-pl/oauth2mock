package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/axent-pl/oauth2mock/handler"
	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/jwk"
	"github.com/axent-pl/oauth2mock/routing"
	"github.com/axent-pl/oauth2mock/server"
	"github.com/axent-pl/oauth2mock/template"
)

var (
	serverAddress string = ":8080"

	dataFile    string = "data/config.json"
	keyFile     string = "data/key.pem"
	templateDir string = "data"

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
	clientStore = auth.NewClientSimpleStore(dataFile)
	subjectStore = auth.NewSubjectSimpleStorer(dataFile)
	claimStore = auth.NewClaimSimpleStorer(dataFile)
	templateStore = template.MustNewDefaultTemplateStore(templateDir)
}

// JWK
func init() {
	key = jwk.MustLoadOrGenerate(keyFile)
}

// Configure HTTP router and server
func init() {
	router = routing.Router{}
	router.RegisterHandler(
		handler.JWKSGetHandler(&key),
		routing.WithMethod(http.MethodGet),
		routing.WithPath("/.well-known/jwks.json"))
	router.RegisterHandler(
		handler.AuthorizeGetHandler(templateStore, clientStore),
		routing.WithMethod(http.MethodGet),
		routing.WithPath("/authorize"),
		routing.ForQueryValue("response_type", "code"))
	router.RegisterHandler(
		handler.AuthorizePostHandler(templateStore, clientStore, subjectStore, authCodeStore),
		routing.WithMethod(http.MethodPost),
		routing.WithPath("/authorize"),
		routing.ForQueryValue("response_type", "code"))
	router.RegisterHandler(
		handler.TokenAuthorizationCodeHandler(clientStore, authCodeStore, claimStore, &key),
		routing.WithMethod(http.MethodPost),
		routing.WithPath("/token"),
		routing.ForPostFormValue("grant_type", "authorization_code"))

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
