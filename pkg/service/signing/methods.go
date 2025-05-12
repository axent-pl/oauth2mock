package signing

type SigningMethod string
type KeyType string

const (
	RS256 SigningMethod = "RS256"
	RS384 SigningMethod = "RS384"
	RS512 SigningMethod = "RS512"

	ES256 SigningMethod = "ES256"
	ES384 SigningMethod = "ES384"
	ES512 SigningMethod = "ES512"

	PS256 SigningMethod = "PS256"
	PS384 SigningMethod = "PS384"
	PS512 SigningMethod = "PS512"
)

const (
	RSA256 KeyType = "RSA256"
	RSA384 KeyType = "RSA384"
	RSA512 KeyType = "RSA512"

	P256 KeyType = "P-256"
	P384 KeyType = "P-384"
	P521 KeyType = "P-521"
)

var SigningMethodKeyTypeCompatibility = map[SigningMethod][]KeyType{
	// RSA PKCS#1 v1.5
	RS256: {RSA256, RSA384, RSA512},
	RS384: {RSA384, RSA512},
	RS512: {RSA512},

	// ECDSA
	ES256: {P256},
	ES384: {P384},
	ES512: {P521},

	// RSA-PSS
	PS256: {RSA256, RSA384, RSA512},
	PS384: {RSA384, RSA512},
	PS512: {RSA512},
}

var KeyTypeSigningMethodCompatibility = map[KeyType][]SigningMethod{
	// RSA keys
	RSA256: {RS256, PS256},
	RSA384: {RS256, RS384, PS256, PS384},
	RSA512: {RS256, RS384, RS512, PS256, PS384, PS512},

	// EC keys
	P256: {ES256},
	P384: {ES384},
	P521: {ES512},
}
