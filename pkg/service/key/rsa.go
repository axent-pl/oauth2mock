package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

type keyHandlerRSA struct {
	privateKey    *rsa.PrivateKey
	signingMethod SignMethod
	id            string
}

func NewFromFile(path string) (KeyHandler, error) {
	kh := &keyHandlerRSA{}
	// read
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// decode
	block, _ := pem.Decode(data)
	if err != nil {
		return nil, err
	}
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key file")
	}
	// parse
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	kh.privateKey = privateKey
	// init
	err = kh.init()
	if err != nil {
		return nil, err
	}
	return kh, nil
}

func NewFromPrivateKey(privateKey *rsa.PrivateKey) (KeyHandler, error) {
	kh := &keyHandlerRSA{
		privateKey: privateKey,
	}
	err := kh.init()
	if err != nil {
		return nil, err
	}
	return kh, nil
}

func NewFromRandom(signingMethod SignMethod) (KeyHandler, error) {
	kh := &keyHandlerRSA{}
	switch signingMethod {
	case RS256:
		kh.privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	case RS384:
		kh.privateKey, _ = rsa.GenerateKey(rand.Reader, 3072)
	case RS512:
		kh.privateKey, _ = rsa.GenerateKey(rand.Reader, 4096)
	}
	err := kh.init()
	if err != nil {
		return nil, err
	}
	return kh, nil
}

func (kh *keyHandlerRSA) init() error {
	// Calculate signing method
	switch kh.privateKey.Size() {
	case 256:
		kh.signingMethod = RS256
	case 384:
		kh.signingMethod = RS384
	case 512:
		kh.signingMethod = RS512
	default:
		return fmt.Errorf("unsupported key size %d", kh.privateKey.Size())
	}

	// Calculate ID
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&kh.privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	kh.id = fmt.Sprintf("%x", sha256.Sum256(publicKeyBytes))

	return nil
}

func (kh *keyHandlerRSA) GetSigningMethod() SignMethod {
	return kh.signingMethod
}

func (kh *keyHandlerRSA) GetID() string {
	return kh.id
}

func (kh *keyHandlerRSA) GetKey() any {
	return kh.privateKey
}
