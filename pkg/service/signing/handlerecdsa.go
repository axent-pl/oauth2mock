package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

type ecdsaSigningKey struct {
	privateKey    *ecdsa.PrivateKey
	signingMethod SigningMethod
	id            string
}

func NewECDSASigningKeyFromFile(path string) (SigningKeyHandler, error) {
	kh := &ecdsaSigningKey{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing ECDSA private key")
	}
	if block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("invalid private key file")
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	kh.privateKey = privateKey
	err = kh.init()
	if err != nil {
		return nil, err
	}
	return kh, nil
}

func NewECDSASigningKeyFromPrivateKey(privateKey *ecdsa.PrivateKey) (SigningKeyHandler, error) {
	kh := &ecdsaSigningKey{privateKey: privateKey}
	if err := kh.init(); err != nil {
		return nil, err
	}
	return kh, nil
}

func NewECDSASigningKeyFromRandom(signingMethod SigningMethod) (SigningKeyHandler, error) {
	kh := &ecdsaSigningKey{}
	var curve elliptic.Curve
	switch signingMethod {
	case ES256:
		curve = elliptic.P256()
	case ES384:
		curve = elliptic.P384()
	case ES521:
		curve = elliptic.P521()
	default:
		return nil, errors.New("unsupported signing method")
	}
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	kh.privateKey = privateKey
	if err := kh.init(); err != nil {
		return nil, err
	}
	return kh, nil
}

func (kh *ecdsaSigningKey) init() error {
	bitSize := kh.privateKey.Curve.Params().BitSize
	slog.Info("Initializing ECDSA key", "BitSize", bitSize)

	switch bitSize {
	case 256:
		kh.signingMethod = ES256
	case 384:
		kh.signingMethod = ES384
	case 521:
		kh.signingMethod = ES521
	default:
		return fmt.Errorf("unsupported curve bit size %d", bitSize)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&kh.privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	kh.id = fmt.Sprintf("%x", sha256.Sum256(pubKeyBytes))
	return nil
}

func (kh *ecdsaSigningKey) GetSigningMethod() SigningMethod {
	return kh.signingMethod
}

func (kh *ecdsaSigningKey) GetID() string {
	return kh.id
}

func (kh *ecdsaSigningKey) GetKey() any {
	return kh.privateKey
}

func (kh *ecdsaSigningKey) Save(path string) error {
	privateKeyBytes, err := x509.MarshalECPrivateKey(kh.privateKey)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}
