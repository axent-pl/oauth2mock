package signing

import (
	"errors"
	"log/slog"
)

type FromPEMConfig struct {
	Path string `json:"path"`
}

func (c *FromPEMConfig) Init() (SigningKeyHandler, error) {
	return NewSigningKeyHandlerFromFile(c.Path)
}

func NewSigningKeyHandlerFromFile(path string) (SigningKeyHandler, error) {
	slog.Info("loading key from file", "path", path)

	// try loading RSA
	if handler, err := NewRSASigningKeyFromFile(path); err == nil {
		return handler, nil
	}
	// try loading EC
	if handler, err := NewECDSASigningKeyFromFile(path); err == nil {
		return handler, nil
	}

	return nil, errors.New("unsupported pem file")
}

func init() {
	RegisterSigningKeyProvider("fromPEM", func() SigningKeyProvider { return &FromPEMConfig{} })
}
