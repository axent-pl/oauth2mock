package signing

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
)

type rsaSigningKey struct {
	privateKey *rsa.PrivateKey
	id         string
	keyType    KeyType
}

func NewRSASigningKeyFromFile(path string) (SigningKeyHandler, error) {
	slog.Info("loading RSA key from file", "path", path)
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

func NewRSASigningKeyFromRandom(keyType KeyType, randReader io.Reader) (SigningKeyHandler, error) {
	slog.Info("generating RSA key from random", "keyType", keyType)
	kh := &rsaSigningKey{}
	switch keyType {
	case RSA256:
		kh.privateKey, _ = rsa.GenerateKey(randReader, 2048)
	case RSA384:
		kh.privateKey, _ = rsa.GenerateKey(randReader, 3072)
	case RSA512:
		kh.privateKey, _ = rsa.GenerateKey(randReader, 4096)
	}
	err := kh.init()
	if err != nil {
		return nil, err
	}
	return kh, nil
}

func (kh *rsaSigningKey) init() error {
	slog.Info("initializing RSA key", "N.BitLen", kh.privateKey.N.BitLen(), "Size", kh.privateKey.Size(), "D.BitLen", kh.privateKey.D.BitLen())

	// Calculate key type
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

	// Calculate key id
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

func (kh *rsaSigningKey) GetPublicKey() any {
	return &kh.privateKey.PublicKey
}

func (kh *rsaSigningKey) Save(paths ...string) error {
	if len(paths) != 1 {
		return errors.New("exactly one path is required: keyPath")
	}
	path := paths[0]

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(kh.privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
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
