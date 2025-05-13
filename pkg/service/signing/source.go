package signing

// SigningKeySourcer interface for construction of SigningKeyHandler from configuration
type SigningKeySourcer interface {
	Init(keyType KeyType) (SigningKeyHandler, error)
}

// map of registered SigningKeyHandler sources
var signingKeySourceRegistry = make(map[string]func() SigningKeySourcer)

func RegisterSigningKeySource(name string, constructor func() SigningKeySourcer) {
	signingKeySourceRegistry[name] = constructor
}
