package main

import (
	"log/slog"
	"os"

	"github.com/axent-pl/oauth2mock/pkg/service/signing"
)

func init() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	jsonLogger := slog.New(jsonHandler)
	slog.SetDefault(jsonLogger)
}

func main() {
	path := "assets/key.pem"
	key, err := signing.NewRSASigningKeyFromRandom(signing.RS512)
	if err != nil {
		slog.Error("failed to generate signing key", "error", err)
		os.Exit(1)
	}
	err = key.Save(path)
	if err != nil {
		slog.Error("failed to save signing key to file", "error", err)
		os.Exit(1)
	}
}
