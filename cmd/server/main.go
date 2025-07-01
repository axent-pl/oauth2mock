package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/axent-pl/oauth2mock/pkg/auth"
	"github.com/axent-pl/oauth2mock/pkg/claimservice"
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/config"
	"github.com/axent-pl/oauth2mock/pkg/handler"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/http/server"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
	"github.com/axent-pl/oauth2mock/pkg/service/template"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type Settings struct {
	DataFile      string `env:"DATAFILE_PATH" default:"assets/config/config.json"`
	ServerAddress string `env:"SERVER_ADDRESS" default:":8222"`
	TemplateDir   string `env:"TEMPLATES_PATH" default:"assets/template"`

	UseOrigin bool   `env:"OAUTH2_ISSUER_FROM_ORIGIN" default:"true"`
	Issuer    string `env:"OAUTH2_ISSUER"`
}

var (
	settings Settings

	authCodeService auth.AuthorizationCodeServicer
	clientService   clientservice.ClientServicer
	userService     userservice.UserServicer
	claimService    claimservice.ClaimServicer
	templateService template.TemplateServicer
	signingService  signing.SigningServicer

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

	data, err := os.ReadFile(settings.DataFile)
	if err != nil {
		slog.Error("failed to read config", "error", err)
		os.Exit(1)
	}

	authCodeService, err = auth.NewAuthorizationCodeService()
	if err != nil {
		slog.Error("failed to initialize authorization code service", "error", err)
		os.Exit(1)
	}
	slog.Info("authorization code service initialized")

	clientService, err = clientservice.NewClientService(settings.DataFile)
	if err != nil {
		slog.Error("failed to initialize client service", "error", err)
		os.Exit(1)
	}
	slog.Info("client service initialized")

	userService, err = userservice.NewFromConfig(data)
	if err != nil {
		slog.Error("failed to initialize user service", "error", err)
		os.Exit(1)
	}
	slog.Info("user service initialized")

	claimService, err = claimservice.NewFromConfig(data)
	if err != nil {
		slog.Error("failed to initialize claim service", "error", err)
		os.Exit(1)
	}
	slog.Info("claimservice initialization done")

	templateService, err = template.NewDefaultTemplateService(settings.TemplateDir)
	if err != nil {
		slog.Error("failed to initialize template service", "error", err)
		os.Exit(1)
	}
	slog.Info("template service initialized")

	signingService, err = signing.NewSigningService(settings.DataFile)
	if err != nil {
		slog.Error("failed to initialize signing service", "error", err)
		os.Exit(1)
	}
	slog.Info("signing initialized")
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
		IdTokenSigningAlgValuesSupported: signingService.GetSigningMethods(),
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
		handler.JWKSGetHandler(signingService),
		routing.WithMethod(http.MethodGet),
		routing.WithPath(openidConfiguration.JWKSEndpoint))

	router.RegisterHandler(
		handler.AuthorizeGetHandler(templateService, clientService),
		routing.WithMethod(http.MethodGet),
		routing.WithPath(openidConfiguration.AuthorizationEndpoint),
		routing.ForQueryValue("response_type", "code"))

	router.RegisterHandler(
		handler.AuthorizePostHandler(templateService, clientService, userService, authCodeService),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.AuthorizationEndpoint),
		routing.ForQueryValue("response_type", "code"))

	router.RegisterHandler(
		handler.TokenAuthorizationCodeHandler(openidConfiguration, clientService, authCodeService, claimService, signingService),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.TokenEndpoint),
		routing.ForPostFormValue("grant_type", "authorization_code"))

	router.RegisterHandler(
		handler.TokenClientCredentialsHandler(openidConfiguration, clientService, claimService, signingService),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.TokenEndpoint),
		routing.ForPostFormValue("grant_type", "client_credentials"))

	router.RegisterHandler(
		handler.TokenPasswordHandler(openidConfiguration, clientService, userService, claimService, signingService),
		routing.WithMethod(http.MethodPost),
		routing.WithPath(openidConfiguration.TokenEndpoint),
		routing.ForPostFormValue("grant_type", "password"))

	router.RegisterHandler(
		handler.SCIMGetHandler(userService),
		routing.WithMethod(http.MethodGet),
		routing.WithPath("/beta/scim/users"))
	router.RegisterHandler(
		handler.SCIMPostHandler(userService),
		routing.WithMethod(http.MethodPost),
		routing.WithPath("/beta/scim/users"))

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
