package signing

import (
	"encoding/json"
	"fmt"

	"maps"

	"github.com/golang-jwt/jwt/v5"
)

type defaultSiginingService struct {
	key SigningKeyHandler
}

func NewDefaultSigningService(key SigningKeyHandler) (SigningServicer, error) {
	s := &defaultSiginingService{
		key: key,
	}
	return s, nil
}

func (s *defaultSiginingService) GetJWKS() ([]byte, error) {
	jwks := JSONWebKeySet{
		Keys: []SigningKeyHandler{s.key},
	}

	return json.Marshal(jwks)
}

func (s *defaultSiginingService) GetSigningMethods() []string {
	return []string{string(s.key.GetSigningMethod())}
}

func (s *defaultSiginingService) Sign(payload map[string]any) ([]byte, error) {
	claims := jwt.MapClaims{}
	maps.Copy(claims, payload)

	signingMethod, err := toJWTSigningMethod(s.key.GetSigningMethod())
	if err != nil {
		return nil, fmt.Errorf("failed to map JWT signing method: %w", err)
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	tokenString, err := token.SignedString(s.key.GetKey())
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	return []byte(tokenString), nil
}

func (s *defaultSiginingService) SignWithMethod(payload map[string]any, method SigningMethod) ([]byte, error) {
	if method != s.key.GetSigningMethod() {
		return nil, fmt.Errorf("unsupported signing method %s", method)
	}
	return s.Sign(payload)
}
