package signing

type FromCertPEMConfig struct {
	CertPath string `json:"certPath"`
	KeyPath  string `json:"keyPath"`
}

func (c *FromCertPEMConfig) Init() (SigningKeyHandler, error) {
	return NewCertSigningKeyFromFiles(c.CertPath, c.KeyPath)
}

func init() {
	RegisterSigningKeyProvider("fromCertPEM", func() SigningKeyProvider { return &FromCertPEMConfig{} })
}
