package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

type rsapssSigningKey struct {
	privateKey    *rsa.PrivateKey
	signingMethod SigningMethod
	id            string
}

func NewRSAPSSSigningKeyFromFile(path string) (SigningKeyHandler, error) {
	kh := &rsapssSigningKey{}
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

func NewRSAPSSSigningKeyFromPrivateKey(privateKey *rsa.PrivateKey) (SigningKeyHandler, error) {
	kh := &rsapssSigningKey{
		privateKey: privateKey,
	}
	err := kh.init()
	if err != nil {
		return nil, err
	}
	return kh, nil
}

func NewRSAPSSSigningKeyFromRandom(signingMethod SigningMethod) (SigningKeyHandler, error) {
	kh := &rsapssSigningKey{}
	switch signingMethod {
	case PS256:
		kh.privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	case PS384:
		kh.privateKey, _ = rsa.GenerateKey(rand.Reader, 3072)
	case PS512:
		kh.privateKey, _ = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unsupported signing method %s", signingMethod)
	}
	err := kh.init()
	if err != nil {
		return nil, err
	}
	return kh, nil
}

func (kh *rsapssSigningKey) init() error {
	// Calculate signing method
	slog.Info("Initializing RSA-PSS key", "N.BitLen", kh.privateKey.N.BitLen(), "Size", kh.privateKey.Size(), "D.BitLen", kh.privateKey.D.BitLen())
	switch kh.privateKey.N.BitLen() {
	case 4096:
		kh.signingMethod = PS512
	case 3072:
		kh.signingMethod = PS384
	case 2048:
		kh.signingMethod = PS256
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

func (kh *rsapssSigningKey) GetSigningMethod() SigningMethod {
	return kh.signingMethod
}

func (kh *rsapssSigningKey) GetID() string {
	return kh.id
}

func (kh *rsapssSigningKey) GetKey() any {
	return kh.privateKey
}

func (kh *rsapssSigningKey) Save(path string) error {
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

func (kh *rsapssSigningKey) MarshalJSON() ([]byte, error) {
	var raw *JSONWebKey = &JSONWebKey{
		Kty: "RSA",
		Kid: kh.id,
		Alg: string(kh.signingMethod),
		Use: "sig",
	}

	// modulus
	raw.N = &byteBuffer{data: kh.privateKey.PublicKey.N.Bytes()}

	// exponent
	raw.E = &byteBuffer{data: make([]byte, 8)}
	binary.BigEndian.PutUint64(raw.E.data, uint64(kh.privateKey.PublicKey.E))

	return json.Marshal(raw)
}
