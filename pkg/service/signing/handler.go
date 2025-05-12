package signing

import "errors"

func NewSigningKeyFromRandom(keyType KeyType) (SigningKeyHandler, error) {
	switch keyType {
	case RSA256, RSA384, RSA512:
		return NewRSASigningKeyFromRandom(keyType)
	case P256, P384, P521:
		return NewECDSASigningKeyFromRandom(keyType)
	default:
		return nil, errors.New("unsupported signing method")
	}
}
