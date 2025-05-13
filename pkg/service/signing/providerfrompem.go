package signing

import (
	"fmt"
	"log/slog"
)

type FromPEMConfig struct {
	Path string `json:"path"`
}

func (c *FromPEMConfig) Init(keyType KeyType) (SigningKeyHandler, error) {
	return NewSigningKeyHandlerFromFile(keyType, c.Path)
}

func NewSigningKeyHandlerFromFile(keyType KeyType, path string) (SigningKeyHandler, error) {
	slog.Info("loading key from file", "keyType", keyType, "path", path)
	switch keyType {
	case RSA256, RSA384, RSA512:
		handler, err := NewRSASigningKeyFromFile(path)
		if err == nil && keyType != handler.GetType() {
			return nil, fmt.Errorf("want %s key, got %s key from file", keyType, handler.GetType())
		}
		return handler, err
	case P256, P384, P521:
		handler, err := NewECDSASigningKeyFromFile(path)
		if err == nil && keyType != handler.GetType() {
			return nil, fmt.Errorf("want %s key, got %s key from file", keyType, handler.GetType())
		}
		return handler, err
	default:
		return nil, fmt.Errorf("unsupported key type %s", keyType)
	}
}

func init() {
	RegisterSigningKeyProvider("fromPEM", func() SigningKeyProvider { return &FromPEMConfig{} })
}
