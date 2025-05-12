package signing

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type siginingServiceKeyConfig struct {
	Path   string        `json:"path"`
	Type   string        `json:"type"`
	Method SigningMethod `json:"method"`
	Active bool          `json:"active"`
}

type siginingServiceKey struct {
	config  siginingServiceKeyConfig
	handler SigningKeyHandler
}

type siginingService struct {
	keys []siginingServiceKey
}

func NewSigingService(jsonFilepath string) (SigningServicer, error) {
	type jsonSigingServiceConfigStruct struct {
		Keys []siginingServiceKeyConfig `json:"keys"`
	}
	type jsonConfigStruct struct {
		Signing jsonSigingServiceConfigStruct `json:"Signing"`
	}
	f := jsonConfigStruct{}

	data, err := os.ReadFile(jsonFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing config file: %w", err)
	}

	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse signing config file: %w", err)
	}

	s := &siginingService{}

	for _, keyConfig := range f.Signing.Keys {
		switch keyConfig.Type {
		case "RSA":
			key, err := NewRSASigningKeyFromFileAndMethod(keyConfig.Path, keyConfig.Method)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize RSA key: %w", err)
			}
			signingKey := siginingServiceKey{config: keyConfig, handler: key}
			s.keys = append(s.keys, signingKey)
		case "ECDSA":
			key, err := NewECDSASigningKeyFromFileAndMethod(keyConfig.Path, keyConfig.Method)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize ECDSA key: %w", err)
			}
			signingKey := siginingServiceKey{config: keyConfig, handler: key}
			s.keys = append(s.keys, signingKey)
		default:
			return nil, fmt.Errorf("unsupported key key type: %s", keyConfig.Type)
		}
	}

	return s, nil
}

func (s *siginingService) getActiveKey() (siginingServiceKey, error) {
	for _, k := range s.keys {
		if k.config.Active {
			return k, nil
		}
	}

	return siginingServiceKey{}, errors.New("no active signing key")
}

func (s *siginingService) getActiveKeyByMethod(method SigningMethod) (siginingServiceKey, error) {
	for _, k := range s.keys {
		if k.config.Active && k.config.Method == method {
			return k, nil
		}
	}
	return siginingServiceKey{}, fmt.Errorf("no active signing key for method: %s", method)
}

func (s *siginingService) GetJWKS() ([]byte, error) {
	keys := make([]JSONWebKey, len(s.keys))
	for i, k := range s.keys {
		keys[i] = k.handler.GetJWK()
		keys[i].Alg = string(k.config.Method)
	}

	jwks := JSONWebKeySet{
		Keys: keys,
	}

	return json.Marshal(jwks)
}

func (s *siginingService) GetSigningMethods() []string {
	methods := make([]string, len(s.keys))
	for i, k := range s.keys {
		methods[i] = string(k.config.Method)
	}
	return methods
}

func (s *siginingService) Sign(payload map[string]any) ([]byte, error) {
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

func (s *siginingService) SignWithMethod(payload map[string]any, method SigningMethod) ([]byte, error) {
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
