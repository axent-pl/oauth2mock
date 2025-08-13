package signing

type SigningKeyHandler interface {
	GetID() string
	GetKey() any
	GetPublicKey() any
	GetType() KeyType
	GetJWK() JSONWebKey
	Save(paths ...string) error
}

type SigningServicer interface {
	GetJWKS() ([]byte, error)
	GetSigningMethods() []string
	Sign(payload map[string]any) ([]byte, error)
	Valid(tokenBytes []byte) bool
	SignWithMethod(payload map[string]any, method SigningMethod) ([]byte, error)
}
