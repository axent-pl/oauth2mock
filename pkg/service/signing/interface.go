package signing

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
)

type SigningMethod string

const (
	RS256 SigningMethod = "RS256"
	RS384 SigningMethod = "RS384"
	RS512 SigningMethod = "RS512"

	ES256 SigningMethod = "ES256"
	ES384 SigningMethod = "ES384"
	ES512 SigningMethod = "ES512"
)

type byteBuffer struct {
	data []byte
}

func (b *byteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

func (b *byteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

type JSONWebKey struct {
	Use       string      `json:"use,omitempty"`
	Kty       string      `json:"kty,omitempty"`
	Kid       string      `json:"kid,omitempty"`
	Crv       string      `json:"crv,omitempty"`
	Alg       string      `json:"alg,omitempty"`
	K         *byteBuffer `json:"k,omitempty"`
	X         *byteBuffer `json:"x,omitempty"`
	Y         *byteBuffer `json:"y,omitempty"`
	N         *byteBuffer `json:"n,omitempty"`
	E         *byteBuffer `json:"e,omitempty"`
	X5c       []string    `json:"x5c,omitempty"`
	X5u       *url.URL    `json:"x5u,omitempty"`
	X5tSHA1   string      `json:"x5t,omitempty"`
	X5tSHA256 string      `json:"x5t#S256,omitempty"`
}

type JSONWebKeySet struct {
	Keys []SigningKeyHandler `json:"keys"`
}

type SigningKeyHandler interface {
	GetSigningMethod() SigningMethod
	GetID() string
	GetKey() any
	Save(path string) error
	MarshalJSON() ([]byte, error)
}

type SigningServicer interface {
	GetJWKS() ([]byte, error)
	GetSigningMethods() []string
	Sign(payload map[string]any) ([]byte, error)
	SignWithMethod(payload map[string]any, method SigningMethod) ([]byte, error)
}
