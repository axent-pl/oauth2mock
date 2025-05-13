package signing

type FromCertPEMConfig struct {
	CertPath string `json:"certPath"`
	KeyPath  string `json:"keyPath"`
}

func (c *FromCertPEMConfig) Init(keyType KeyType) (SigningKeyHandler, error) {
	return NewCertSigningKeyFromFiles(c.CertPath, c.KeyPath)
}

func init() {
	RegisterSigningKeySource("fromCertPEM", func() SigningKeySourcer { return &FromCertPEMConfig{} })
}
