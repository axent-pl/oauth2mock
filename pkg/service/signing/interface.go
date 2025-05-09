package signing

type SigningMethod string

const (
	RS256 SigningMethod = "RS256"
	RS384 SigningMethod = "RS384"
	RS512 SigningMethod = "RS512"

	ES256 SigningMethod = "ES256"
	ES384 SigningMethod = "ES384"
	ES512 SigningMethod = "ES512"
)

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
