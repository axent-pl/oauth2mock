package signing

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type signingService struct {
	// here we need configuration (and below the implementation) of the key rotation (roundrobin, ...)
	keys []signingServiceKey
}

type signingServiceKey struct {
	config  SigningServiceKeyConfig
	handler SigningKeyHandler
}

func NewSigningService(jsonFilepath string) (SigningServicer, error) {
	type jsonConfigStruct struct {
		Signing struct {
			Keys []SigningServiceKeyConfig `json:"keys"`
		} `json:"Signing"`
	}
	f := jsonConfigStruct{}

	data, err := os.ReadFile(jsonFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing config file: %w", err)
	}

	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse signing config file: %w", err)
	}

	s := &signingService{}

	for _, keyConfig := range f.Signing.Keys {
		signingKey, err := keyConfig.Source.Init(keyConfig.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize signing key: %w", err)
		}
		s.keys = append(s.keys, signingServiceKey{config: keyConfig, handler: signingKey})
	}

	return s, nil
}

func (s *signingService) getActiveKey() (signingServiceKey, error) {
	for _, k := range s.keys {
		if k.config.Active {
			return k, nil
		}
	}

	return signingServiceKey{}, errors.New("no active signing key")
}

func (s *signingService) getActiveKeyByMethod(method SigningMethod) (signingServiceKey, error) {
	for _, k := range s.keys {
		if k.config.Active && k.config.Method == method {
			return k, nil
		}
	}
	return signingServiceKey{}, fmt.Errorf("no active signing key for method: %s", method)
}

func (s *signingService) GetJWKS() ([]byte, error) {
	jwks := JSONWebKeySet{
		Keys: make([]JSONWebKey, len(s.keys)),
	}

	for i, k := range s.keys {
		jwks.Keys[i] = k.handler.GetJWK()
		jwks.Keys[i].Alg = string(k.config.Method)
	}

	return json.Marshal(jwks)
}

func (s *signingService) GetSigningMethods() []string {
	methods := make([]string, len(s.keys))
	for i, k := range s.keys {
		methods[i] = string(k.config.Method)
	}
	return methods
}

func (s *signingService) Sign(payload map[string]any) ([]byte, error) {
	claims := jwt.MapClaims{}
	maps.Copy(claims, payload)

	key, err := s.getActiveKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}

	signingMethod, err := toJWTSigningMethod(key.config.Method)
	if err != nil {
		return nil, fmt.Errorf("failed to map signing method: %w", err)
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	tokenString, err := token.SignedString(key.handler.GetKey())
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	return []byte(tokenString), nil
}

func (s *signingService) SignWithMethod(payload map[string]any, method SigningMethod) ([]byte, error) {
	claims := jwt.MapClaims{}
	maps.Copy(claims, payload)

	key, err := s.getActiveKeyByMethod(method)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}

	signingMethod, err := toJWTSigningMethod(method)
	if err != nil {
		return nil, fmt.Errorf("failed to map signing method: %w", err)
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	tokenString, err := token.SignedString(key.handler.GetKey())
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	return []byte(tokenString), nil
}
