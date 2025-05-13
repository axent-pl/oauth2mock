package signing

import (
	"fmt"
	"log/slog"
)

type FromRandomConfig struct {
	Deterministic bool   `json:"deterministic"`
	Seed          string `json:"seed"`
}

func (config *FromRandomConfig) Init(keyType KeyType) (SigningKeyHandler, error) {
	return NewSigningKeyHandlerFromRandom(keyType, config.Deterministic, config.Seed)
}

func NewSigningKeyHandlerFromRandom(keyType KeyType, deterministic bool, seed string) (SigningKeyHandler, error) {
	slog.Info("generating key from random", "keyType", keyType, "deterministic", deterministic, "seed", seed)
	switch keyType {
	case RSA256, RSA384, RSA512:
		handler, err := NewRSASigningKeyFromRandom(keyType, NewRandReader(deterministic, seed))
		if err == nil && keyType != handler.GetType() {
			return nil, fmt.Errorf("want %s key, got %s key from file", keyType, handler.GetType())
		}
		return handler, err
	case P256, P384, P521:
		handler, err := NewECDSASigningKeyFromRandom(keyType, NewRandReader(deterministic, seed))
		if err == nil && keyType != handler.GetType() {
			return nil, fmt.Errorf("want %s key, got %s key from file", keyType, handler.GetType())
		}
		return handler, err
	default:
		return nil, fmt.Errorf("unsupported key type %s", keyType)
	}
}

func init() {
	RegisterSigningKeySource("fromRandom", func() SigningKeySourcer { return &FromRandomConfig{} })
}
