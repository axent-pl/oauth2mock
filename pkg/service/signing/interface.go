package signing

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
