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
