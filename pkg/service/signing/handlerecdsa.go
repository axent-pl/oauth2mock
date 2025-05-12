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
	privateKey *ecdsa.PrivateKey
	keyType    KeyType
	id         string
}

func NewECDSASigningKeyFromFileAndMethod(path string, method SigningMethod) (SigningKeyHandler, error) {
	key, err := NewECDSASigningKeyFromFile(path)
	if err != nil {
		return nil, err
	}

	if IsKeyCompatible(method, key.GetType()) {
		return key, nil
	}

	return nil, fmt.Errorf("given method %s does not match the key type and length %s", method, key.GetType())
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

func NewECDSASigningKeyFromRandom(keyType KeyType) (SigningKeyHandler, error) {
	kh := &ecdsaSigningKey{}
	var curve elliptic.Curve
	switch keyType {
	case P256:
		curve = elliptic.P256()
	case P384:
		curve = elliptic.P384()
	case P521:
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
	slog.Info("initializing ECDSA key", "BitSize", bitSize)

	switch bitSize {
	case 256:
		kh.keyType = P256
	case 384:
		kh.keyType = P384
	case 521:
		kh.keyType = P521
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

func (kh *ecdsaSigningKey) GetType() KeyType {
	return kh.keyType
}

func (kh *ecdsaSigningKey) getCurveName() string {
	return string(kh.keyType)
}

func (kh *ecdsaSigningKey) getCurveByteSize() int {
	return (kh.privateKey.Curve.Params().Params().BitSize + 7) / 8
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

func (kh *ecdsaSigningKey) GetJWK() JSONWebKey {
	var raw JSONWebKey = JSONWebKey{
		Kty: "EC",
		Kid: kh.id,
		Use: "sig",
	}

	// curve name
	raw.Crv = kh.getCurveName()

	// X
	raw.X = &byteBuffer{data: make([]byte, kh.getCurveByteSize())}
	padX := make([]byte, kh.getCurveByteSize()-len(kh.privateKey.PublicKey.X.Bytes()))
	raw.X.data = append(padX, kh.privateKey.PublicKey.X.Bytes()...)

	// Y
	raw.Y = &byteBuffer{data: make([]byte, kh.getCurveByteSize())}
	padY := make([]byte, kh.getCurveByteSize()-len(kh.privateKey.PublicKey.Y.Bytes()))
	raw.Y.data = append(padY, kh.privateKey.PublicKey.Y.Bytes()...)

	return raw
}
