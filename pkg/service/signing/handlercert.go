package signing

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"time"
)

type certSigningKey struct {
	privateKey  crypto.PrivateKey
	certificate *x509.Certificate
	id          string
	keyType     KeyType
}

// NewCertSigningKeyFromFiles loads key and cert from PEM-encoded files
func NewCertSigningKeyFromFiles(certPath, keyPath string) (SigningKeyHandler, error) {
	slog.Info("loading cert and key from files", "certPath", certPath, "keyPath", keyPath)

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading cert file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	return NewCertSigningKeyFromPEM(certPEM, keyPEM)
}

func NewCertSigningKeyFromPEM(certPEM, keyPEM []byte) (SigningKeyHandler, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	var priv crypto.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		priv, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	return newCertSigningKey(cert, priv)
}

// NewCertSigningKeyFromTLS accepts a tls.Certificate
func NewCertSigningKeyFromTLS(tlsCert tls.Certificate) (SigningKeyHandler, error) {
	if len(tlsCert.Certificate) == 0 || tlsCert.PrivateKey == nil {
		return nil, errors.New("invalid TLS certificate: missing certificate or private key")
	}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return newCertSigningKey(cert, tlsCert.PrivateKey)
}

// NewCertSigningKeyFromRandom generates an RSA key and self-signed cert
func NewCertSigningKeyFromRandom(keyType KeyType, randReader io.Reader) (SigningKeyHandler, error) {
	var keySize int
	switch keyType {
	case RSA256:
		keySize = 2048
	case RSA384:
		keySize = 3072
	case RSA512:
		keySize = 4096
	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	privateKey, err := rsa.GenerateKey(randReader, keySize)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          bigIntHash(privateKey.N.Bytes()),
		Subject:               pkix.Name{CommonName: "Self-Signed"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(randReader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return newCertSigningKey(cert, privateKey)
}

func newCertSigningKey(cert *x509.Certificate, key crypto.PrivateKey) (SigningKeyHandler, error) {
	kh := &certSigningKey{
		certificate: cert,
		privateKey:  key,
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("unsupported private key type (only RSA supported)")
	}

	switch rsaKey.N.BitLen() {
	case 2048:
		kh.keyType = RSA256
	case 3072:
		kh.keyType = RSA384
	case 4096:
		kh.keyType = RSA512
	default:
		return nil, fmt.Errorf("unsupported RSA key size: %d", rsaKey.N.BitLen())
	}

	// Key ID from public key hash
	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	kh.id = fmt.Sprintf("%x", sha256.Sum256(pubDER))
	return kh, nil
}

func (kh *certSigningKey) GetType() KeyType {
	return kh.keyType
}

func (kh *certSigningKey) GetID() string {
	return kh.id
}

func (kh *certSigningKey) GetKey() any {
	return kh.privateKey
}

func (kh *certSigningKey) Save(paths ...string) error {
	if len(paths) != 2 {
		return errors.New("exactly two paths are required: certPath and keyPath")
	}
	certPath, keyPath := paths[0], paths[1]

	// Save the certificate to the specified path
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating cert file: %w", err)
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: kh.certificate.Raw})
	if err != nil {
		return fmt.Errorf("writing cert to file: %w", err)
	}

	// Save the private key to the specified path
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}
	defer keyOut.Close()

	var keyBlock *pem.Block
	switch key := kh.privateKey.(type) {
	case *rsa.PrivateKey:
		keyBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	default:
		return errors.New("unsupported private key type (only RSA supported)")
	}

	err = pem.Encode(keyOut, keyBlock)
	if err != nil {
		return fmt.Errorf("writing key to file: %w", err)
	}

	return nil
}

func (kh *certSigningKey) GetJWK() JSONWebKey {
	var raw JSONWebKey = JSONWebKey{
		Kty: "RSA",
		Kid: kh.id,
		Use: "sig",
	}
	rsaPub, ok := kh.certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return raw
	}

	raw.N = &byteBuffer{data: rsaPub.N.Bytes()}
	raw.E = &byteBuffer{data: make([]byte, 8)}
	binary.BigEndian.PutUint64(raw.E.data, uint64(rsaPub.E))

	raw.X5c = []string{base64.StdEncoding.EncodeToString(kh.certificate.Raw)}

	return raw
}

// helper to create a deterministic serial number
func bigIntHash(data []byte) *big.Int {
	hash := sha256.Sum256(data)
	return new(big.Int).SetBytes(hash[:])
}
