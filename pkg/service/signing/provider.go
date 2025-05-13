package signing

// SigningKeyProvider interface for construction of SigningKeyHandler from configuration
type SigningKeyProvider interface {
	Init(keyType KeyType) (SigningKeyHandler, error)
}

// map of registered SigningKeyHandler sources
var signingKeyProviderRegistry = make(map[string]func() SigningKeyProvider)

func RegisterSigningKeyProvider(name string, constructor func() SigningKeyProvider) {
	signingKeyProviderRegistry[name] = constructor
}
