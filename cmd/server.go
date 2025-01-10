package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/axent-pl/oauth2mock/auth"
	"github.com/axent-pl/oauth2mock/handler"
	"github.com/axent-pl/oauth2mock/routing"
	"github.com/axent-pl/oauth2mock/server"
	"github.com/axent-pl/oauth2mock/template"
	"github.com/axent-pl/oauth2mock/utils"
)

var (
	keyFile       string
	dataFile      string
	serverAddress string
	templateDir   string

	authCodeStore auth.AuthorizationCodeStorer
	clientStore   auth.ClientStorer
	subjectStore  auth.SubjectStorer
	claimStore    auth.ClaimStorer
	templateStore template.TemplateStorer

	key        auth.JWK
	router     routing.Router
	httpServer server.Server
)

// Load envs
func init() {
	keyFile = utils.GetEnv("KEY_PATH", "data/key.pem")
	dataFile = utils.GetEnv("DATAFILE_PATH", "data/config.json")
	serverAddress = utils.GetEnv("SERVER_ADDRESS", ":8080")
	templateDir = utils.GetEnv("TEMPLATES_PATH", "data")
}

// Configure logger
func init() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	jsonLogger := slog.New(jsonHandler)
	slog.SetDefault(jsonLogger)
}

// Configure stores
func init() {
	var err error

	authCodeStore, err = auth.NewAuthorizationCodeSimpleStore()
	if err != nil {
		slog.Error("failed to initialize authorization code store", "error", err)
		os.Exit(1)
	}
	slog.Info("authorization code store initialized")

	clientStore, err = auth.NewClientSimpleStore(dataFile)
	if err != nil {
		slog.Error("failed to initialize client store", "error", err)
		os.Exit(1)
	}
	slog.Info("client store initialized")

	subjectStore, err = auth.NewSubjectSimpleStorer(dataFile)
	if err != nil {
		slog.Error("failed to initialize subject store", "error", err)
		os.Exit(1)
	}
	slog.Info("subject store initialized")

	claimStore, err = auth.NewClaimSimpleStorer(dataFile)
	if err != nil {
		slog.Error("failed to initialize claim store", "error", err)
		os.Exit(1)
	}
	slog.Info("claim store initialized")

	templateStore, err = template.NewDefaultTemplateStore(templateDir)
	if err != nil {
		slog.Error("failed to initialize template store", "error", err)
		os.Exit(1)
	}
	slog.Info("template store initialized")

	key, err = auth.LoadOrGenerate(keyFile)
	if err != nil {
		slog.Error("failed to load or generate JWK", "error", err)
		os.Exit(1)
	}
	slog.Info("JWK initialized")
}

// Configure HTTP router and server
func init() {
	openidConfiguration := auth.OpenIDConfiguration{
		WellKnownEndpoint:                "/.well-known/openid-configuration",
		AuthorizationEndpoint:            "/authorize",
		TokenEndpoint:                    "/token",
		JWKSEndpoint:                     "/.well-known/jwks.json",
		GrantTypesSupported:              []string{"authorization_code"},
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	router = routing.Router{}
	router.RegisterHandler(
		handler.WellKnownHandler(openidConfiguration),
		routing.WithMethod(http.MethodGet),
		routing.WithPath(openidConfiguration.WellKnownEndpoint))
	router.RegisterHandler(
		handler.JWKSGetHandler(&key),
		routing.WithMethod(http.MethodGet),
		routing.WithPath(openidConfiguration.JWKSEndpoint))
	router.RegisterHandler(
		handler.AuthorizeGetHandler(templateStore, clientStore),
		routing.WithMethod(http.MethodGet),
		routing.WithPath(openidConfiguration.AuthorizationEndpoint),
		routing.ForQueryValue("response_type", "code"))
	router.RegisterHandler(
		handler.AuthorizePostHandler(templateStore, clientStore, subjectStore, authCodeStore),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.AuthorizationEndpoint),
		routing.ForQueryValue("response_type", "code"))
	router.RegisterHandler(
		handler.TokenAuthorizationCodeHandler(clientStore, authCodeStore, claimStore, &key),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.TokenEndpoint))
	// ,routing.ForPostFormValue("grant_type", "authorization_code")

	httpServer = server.Server{
		Addr:   serverAddress,
		Router: router,
	}
}

func main() {
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
