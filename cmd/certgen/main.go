package main

import (
	"log/slog"
	"os"

	"github.com/axent-pl/oauth2mock/pkg/config"
	"github.com/axent-pl/oauth2mock/pkg/service/signing"
)

type Settings struct {
	KeyType  signing.KeyType `env:"KEY_TYPE" default:"RSA256"`
	KeySeed  string          `env:"KEY_SEED" default:""`
	KeyFile  string          `env:"KEY_PATH" default:"assets/key/key.pem"`
	CertFile string          `env:"CERT_PATH" default:"assets/key/cert.pem"`
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
	var deterministic bool = false
	if settings.KeySeed != "" {
		deterministic = true
	}
	key, err := signing.NewCertSigningKeyFromRandom(settings.KeyType, signing.NewRandReader(deterministic, settings.KeySeed))
	if err != nil {
		slog.Error("failed to generate signing key and cert", "error", err)
		os.Exit(1)
	}
	slog.Info("genrated RSA private key", "keyType", key.GetType())

	err = key.Save(settings.CertFile, settings.KeyFile)
	if err != nil {
		slog.Error("failed to save signing key and cert to file", "error", err)
		os.Exit(1)
	}
}
