package signing

import "errors"

func NewSigningKeyFromFile(path string) (SigningKeyHandler, error) {
	if signingKeyHandler, err := NewRSASigningKeyFromFile(path); err == nil {
		return signingKeyHandler, nil
	}
	if signingKeyHandler, err := NewECDSASigningKeyFromFile(path); err == nil {
		return signingKeyHandler, nil
	}
	return nil, errors.New("unsupported signing key file format")
}

func NewSigningKeyFromRandom(signingMethod SigningMethod) (SigningKeyHandler, error) {
	switch signingMethod {
	case RS256, RS384, RS512:
		return NewRSASigningKeyFromRandom(signingMethod)
	case ES256, ES384, ES521:
		return NewECDSASigningKeyFromRandom(signingMethod)
	default:
		return nil, errors.New("unsupported signing method")
	}
}
