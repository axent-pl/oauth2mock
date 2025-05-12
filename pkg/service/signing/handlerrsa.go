package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

type rsaSigningKey struct {
	privateKey *rsa.PrivateKey
	id         string
	keyType    KeyType
}

func NewRSASigningKeyFromFileAndMethod(path string, method SigningMethod) (SigningKeyHandler, error) {
	key, err := NewRSASigningKeyFromFile(path)
	if err != nil {
		return nil, err
	}

	if IsKeyCompatible(method, key.GetType()) {
		return key, nil
	}

	return nil, fmt.Errorf("given method %s does not match the key type and length %s", method, key.GetType())
}

func NewRSASigningKeyFromFile(path string) (SigningKeyHandler, error) {
	kh := &rsaSigningKey{}
	// read
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// decode
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	if block.Type != "RSA PRIVATE KEY" {
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

func NewRSASigningKeyFromPrivateKey(privateKey *rsa.PrivateKey) (SigningKeyHandler, error) {
	kh := &rsaSigningKey{
		privateKey: privateKey,
	}
	err := kh.init()
	if err != nil {
		return nil, err
	}
	return kh, nil
}

func NewRSASigningKeyFromRandom(keyType KeyType) (SigningKeyHandler, error) {
	kh := &rsaSigningKey{}
	switch keyType {
	case RSA256:
		kh.privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	case RSA384:
		kh.privateKey, _ = rsa.GenerateKey(rand.Reader, 3072)
	case RSA512:
		kh.privateKey, _ = rsa.GenerateKey(rand.Reader, 4096)
	}
	err := kh.init()
	if err != nil {
		return nil, err
	}
	return kh, nil
}

func (kh *rsaSigningKey) init() error {
	// Calculate signing method
	slog.Info("Initializing key", "N.BitLen", kh.privateKey.N.BitLen(), "Size", kh.privateKey.Size(), "D.BitLen", kh.privateKey.D.BitLen())
	switch kh.privateKey.N.BitLen() {
	case 4096:
		kh.keyType = RSA512
	case 3072:
		kh.keyType = RSA384
	case 2048:
		kh.keyType = RSA256
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

func (kh *rsaSigningKey) GetType() KeyType {
	return kh.keyType
}

func (kh *rsaSigningKey) GetID() string {
	return kh.id
}

func (kh *rsaSigningKey) GetKey() any {
	return kh.privateKey
}

func (kh *rsaSigningKey) Save(path string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(kh.privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

func (kh *rsaSigningKey) GetJWK() JSONWebKey {
	var raw JSONWebKey = JSONWebKey{
		Kty: "RSA",
		Kid: kh.id,
		Use: "sig",
	}

	// modulus
	raw.N = &byteBuffer{data: kh.privateKey.PublicKey.N.Bytes()}

	// exponent
	raw.E = &byteBuffer{data: make([]byte, 8)}
	binary.BigEndian.PutUint64(raw.E.data, uint64(kh.privateKey.PublicKey.E))

	return raw
}
