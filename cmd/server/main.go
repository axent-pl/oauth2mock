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
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/http/server"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
	"github.com/axent-pl/oauth2mock/pkg/service/template"
)

type Settings struct {
	KeyFile       string `env:"KEY_PATH" default:"assets/key/key.pem"`
	DataFile      string `env:"DATAFILE_PATH" default:"assets/config/config.json"`
	ServerAddress string `env:"SERVER_ADDRESS" default:":8080"`
	TemplateDir   string `env:"TEMPLATES_PATH" default:"assets/template"`

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
	keyHandler      signing.SigningKeyHandler
	keyService      signing.SigningServicer

	router     routing.Router
	httpServer server.Serverer
)

// Configure logger
func init() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	jsonLogger := slog.New(jsonHandler)
	slog.SetDefault(jsonLogger)
}

// Load config settings
func init() {
	err := config.Load(&settings)
	if err != nil {
		slog.Error("failed to load config settings", "error", err)
		os.Exit(1)
	}
	slog.Info("config settings initialized")
}

// Initialize services
func init() {
	var err error

	authCodeService, err = auth.NewAuthorizationCodeSimpleService()
	if err != nil {
		slog.Error("failed to initialize authorization code service", "error", err)
		os.Exit(1)
	}
	slog.Info("authorization code service initialized")

	clientService, err = auth.NewClientService(settings.DataFile)
	if err != nil {
		slog.Error("failed to initialize client service", "error", err)
		os.Exit(1)
	}
	slog.Info("client service initialized")

	subjectService, err = auth.NewUserService(settings.DataFile)
	if err != nil {
		slog.Error("failed to initialize subject service", "error", err)
		os.Exit(1)
	}
	slog.Info("subject service initialized")

	claimService, err = auth.NewClaimService(settings.DataFile)
	if err != nil {
		slog.Error("failed to initialize claim service", "error", err)
		os.Exit(1)
	}
	slog.Info("claim service initialized")

	templateService, err = template.NewDefaultTemplateStore(settings.TemplateDir)
	if err != nil {
		slog.Error("failed to initialize template service", "error", err)
		os.Exit(1)
	}
	slog.Info("template service initialized")

	keyHandler, err = signing.NewSigningKeyFromFile(settings.KeyFile)
	if err != nil {
		slog.Error("failed to load JWK", "error", err)
		os.Exit(1)
	}
	slog.Info("JWK loaded")

	keyService, err = signing.NewDefaultSigningService(keyHandler)
	if err != nil {
		slog.Error("failed to initialize JWK service", "error", err)
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
		IdTokenSigningAlgValuesSupported: keyService.GetSigningMethods(),
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
		handler.JWKSGetHandler(keyService),
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
		handler.TokenAuthorizationCodeHandler(openidConfiguration, clientService, authCodeService, claimService, keyService),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.TokenEndpoint),
		routing.ForPostFormValue("grant_type", "authorization_code"))

	router.RegisterHandler(
		handler.TokenClientCredentialsHandler(openidConfiguration, clientService, claimService, keyService),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.TokenEndpoint),
		routing.ForPostFormValue("grant_type", "client_credentials"))

	router.RegisterHandler(
		handler.TokenPasswordHandler(openidConfiguration, clientService, subjectService, claimService, keyService),
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
