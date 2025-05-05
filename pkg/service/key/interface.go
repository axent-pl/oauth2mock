package key

type SignMethod string

const (
	RS256 SignMethod = "RS256"
	RS384 SignMethod = "RS384"
	RS512 SignMethod = "RS512"

	ES256 SignMethod = "ES256"
	ES384 SignMethod = "ES384"
	ES512 SignMethod = "ES512"
)

type KeyHandler interface {
	GetSigningMethod() SignMethod
	GetID() string
	GetKey() any
}

type JWKServicer interface {
	GetJWKS() ([]byte, error)
	GetSigningMethods() []string
	Sign(payload map[string]any) ([]byte, error)
	SignWithMethod(payload map[string]any, method SignMethod) ([]byte, error)
}
