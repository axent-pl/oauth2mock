package signing

type SigningKeyHandler interface {
	GetID() string
	GetKey() any
	GetType() KeyType
	GetJWK() JSONWebKey
	Save(path string) error
}

type SigningServicer interface {
	GetJWKS() ([]byte, error)
	GetSigningMethods() []string
	Sign(payload map[string]any) ([]byte, error)
	SignWithMethod(payload map[string]any, method SigningMethod) ([]byte, error)
}
