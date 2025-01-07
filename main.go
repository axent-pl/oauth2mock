package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/jwk"
	"github.com/axent-pl/oauth2mock/server"
)

const loginTemplateFile = "tpl/login.go.tpl"

var (
	signalChannel chan os.Signal
	serverAddress string
)

// Configure logger
func init() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	jsonLogger := slog.New(jsonHandler)
	slog.SetDefault(jsonLogger)
}

// Configure server with signalChannel
func init() {
	serverAddress = ":8080"

	signalChannel = make(chan os.Signal)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
}

func main() {
	key := jwk.MustLoadOrGenerate()
	authCodeDB := auth.NewAuthorizationCodeInMemoryStore()
	clientDB := auth.NewClientSimpleStore("run/users.json")
	subjectDB := auth.NewSubjectSimpleStorer()
	claimsDB := auth.NewClaimSimpleStorer("run/users.json")

	router := server.Router{}
	router.RegisterHandler(JWKSGetHandler(&key), server.WithMethod(http.MethodGet), server.WithPath("/.well-known/jwks.json"))
	router.RegisterHandler(AuthorizeGetHandler(clientDB), server.WithMethod(http.MethodGet), server.WithPath("/authorize"), server.ForQueryValue("response_type", "code"))
	router.RegisterHandler(AuthorizePostHandler(clientDB, subjectDB, authCodeDB), server.WithMethod(http.MethodPost), server.WithPath("/authorize"), server.ForQueryValue("response_type", "code"))
	router.RegisterHandler(TokenAuthorizationCodeHandler(clientDB, authCodeDB, claimsDB, &key), server.WithMethod(http.MethodPost), server.WithPath("/token"), server.ForPostFormValue("grant_type", "authorization_code"))

	httpServer := server.Server{
		Addr:   serverAddress,
		Router: router,
	}

	// Init cancellation context triggered by SIGINT or SIGTERM
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-signalChannel
		cancel()
	}()
	defer cancel()

	// start the server
	if err := httpServer.Start(ctx); err != nil {
		os.Exit(1)
	}
}
