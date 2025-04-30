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
	"github.com/axent-pl/oauth2mock/pkg/config"
	"github.com/axent-pl/oauth2mock/routing"
	"github.com/axent-pl/oauth2mock/server"
	"github.com/axent-pl/oauth2mock/template"
)

type Settings struct {
	KeyFile       string `env:"KEY_PATH" default:"data/key.pem"`
	DataFile      string `env:"DATAFILE_PATH" default:"data/config.json"`
	ServerAddress string `env:"SERVER_ADDRESS" default:":8080"`
	TemplateDir   string `env:"TEMPLATES_PATH" default:"data"`

	UseOrigin bool   `env:"OAUTH2_ISSUER_FROM_ORIGIN" default:"true"`
	Issuer    string `env:"OAUTH2_ISSUER"`
}

var (
	settings Settings

	authCodeService auth.AuthorizationCodeService
	clientService   auth.ClientServicer
	subjectService  auth.UserServicer
	claimService    auth.ClaimServicer
	templateService template.TemplateStorer

	key        auth.JWK
	router     routing.Router
	httpServer server.Serverer
)

// Load envs
func init() {
	err := config.Load(&settings)
	if err != nil {
		slog.Error("failed to load config settings", "error", err)
		os.Exit(1)
	}
	slog.Info("config settings initialized")
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

	authCodeService, err = auth.NewAuthorizationCodeSimpleService()
	if err != nil {
		slog.Error("failed to initialize authorization code store", "error", err)
		os.Exit(1)
	}
	slog.Info("authorization code store initialized")

	clientService, err = auth.NewClientService(settings.DataFile)
	if err != nil {
		slog.Error("failed to initialize client store", "error", err)
		os.Exit(1)
	}
	slog.Info("client store initialized")

	subjectService, err = auth.NewUserService(settings.DataFile)
	if err != nil {
		slog.Error("failed to initialize subject store", "error", err)
		os.Exit(1)
	}
	slog.Info("subject store initialized")

	claimService, err = auth.NewClaimService(settings.DataFile)
	if err != nil {
		slog.Error("failed to initialize claim store", "error", err)
		os.Exit(1)
	}
	slog.Info("claim store initialized")

	templateService, err = template.NewDefaultTemplateStore(settings.TemplateDir)
	if err != nil {
		slog.Error("failed to initialize template store", "error", err)
		os.Exit(1)
	}
	slog.Info("template store initialized")

	key, err = auth.LoadOrGenerate(settings.KeyFile)
	if err != nil {
		slog.Error("failed to load or generate JWK", "error", err)
		os.Exit(1)
	}
	slog.Info("JWK initialized")
}

// Configure HTTP router and server
func init() {
	openidConfiguration := auth.OpenIDConfiguration{
		Issuer:                           settings.Issuer,
		UseOrigin:                        settings.UseOrigin,
		WellKnownEndpoint:                "/.well-known/openid-configuration",
		AuthorizationEndpoint:            "/authorize",
		TokenEndpoint:                    "/token",
		JWKSEndpoint:                     "/.well-known/jwks.json",
		GrantTypesSupported:              []string{"authorization_code", "client_credentials", "password"},
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	router = routing.Router{}

	router.RegisterHandler(
		handler.WellKnownHandler(openidConfiguration),
		routing.WithMethod(http.MethodGet),
		routing.WithPath("/"))

	router.RegisterHandler(
		handler.WellKnownHandler(openidConfiguration),
		routing.WithMethod(http.MethodGet),
		routing.WithPath(openidConfiguration.WellKnownEndpoint))

	router.RegisterHandler(
		handler.JWKSGetHandler(&key),
		routing.WithMethod(http.MethodGet),
		routing.WithPath(openidConfiguration.JWKSEndpoint))

	router.RegisterHandler(
		handler.AuthorizeGetHandler(templateService, clientService),
		routing.WithMethod(http.MethodGet),
		routing.WithPath(openidConfiguration.AuthorizationEndpoint),
		routing.ForQueryValue("response_type", "code"))

	router.RegisterHandler(
		handler.AuthorizePostHandler(templateService, clientService, subjectService, authCodeService),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.AuthorizationEndpoint),
		routing.ForQueryValue("response_type", "code"))

	router.RegisterHandler(
		handler.TokenAuthorizationCodeHandler(openidConfiguration, clientService, authCodeService, claimService, &key),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.TokenEndpoint),
		routing.ForPostFormValue("grant_type", "authorization_code"))

	router.RegisterHandler(
		handler.TokenClientCredentialsHandler(openidConfiguration, clientService, claimService, &key),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.TokenEndpoint),
		routing.ForPostFormValue("grant_type", "client_credentials"))

	router.RegisterHandler(
		handler.TokenPasswordHandler(openidConfiguration, clientService, subjectService, claimService, &key),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.TokenEndpoint),
		routing.ForPostFormValue("grant_type", "password"))

	httpServer, _ = server.NewServer(settings.ServerAddress, router)
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
