package main

import (
	"log/slog"
	"os"

	"github.com/axent-pl/oauth2mock/pkg/config"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
)

type Settings struct {
	KeyType signing.SigningMethod `env:"KEY_TYPE" default:"RS256"`
	KeyFile string                `env:"KEY_PATH" default:"assets/key/key.pem"`
}

var settings Settings

func init() {
	err := config.Load(&settings)
	if err != nil {
		slog.Error("failed to load config settings", "error", err)
		os.Exit(1)
	}
}

func init() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	jsonLogger := slog.New(jsonHandler)
	slog.SetDefault(jsonLogger)
}

func main() {
	key, err := signing.NewSigningKeyFromRandom(settings.KeyType)
	if err != nil {
		slog.Error("failed to generate signing key", "error", err)
		os.Exit(1)
	}
	slog.Info("genrated RSA private key", "signingMehtod", key.GetSigningMethod())

	err = key.Save(settings.KeyFile)
	if err != nil {
		slog.Error("failed to save signing key to file", "error", err)
		os.Exit(1)
	}
}
