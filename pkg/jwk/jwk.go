package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	jwt_ext "github.com/golang-jwt/jwt/v5"
	"github.com/square/go-jose/v3"
)

const keyFile = "run/private_key.pem"

type JWK struct {
	privateKey *rsa.PrivateKey
}

func (k *JWK) GetJWKS() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&k.privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	kid := fmt.Sprintf("%x", sha256.Sum256(pubKeyBytes))

	publicKey := jose.JSONWebKey{
		Key:       &k.privateKey.PublicKey,
		Algorithm: string(jose.RS256),
		Use:       "sig",
		KeyID:     kid,
	}

	if !publicKey.Valid() {
		return nil, errors.New("JWK is invalid")
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{publicKey},
	}

	return json.Marshal(jwks)
}

func (k *JWK) SignJWT(payload map[string]interface{}) ([]byte, error) {
	claims := jwt_ext.MapClaims{
		"exp": time.Now().Add(time.Hour * 1).Unix(), // Token expiration
		"iat": time.Now().Unix(),                    // Token issued at
	}

	for key, value := range payload {
		claims[key] = value
	}

	token := jwt_ext.NewWithClaims(jwt_ext.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(k.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	return []byte(tokenString), nil
}

func loadPrivateKeyFromFile(filepath string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key file")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func savePrivateKeyToFile(filepath string, key *rsa.PrivateKey) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

func generatePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func MustLoad() JWK {
	key := JWK{}
	privateKey, err := loadPrivateKeyFromFile(keyFile)
	if err != nil {
		panic(err)
	}
	key.privateKey = privateKey
	return key
}

func MustLoadOrGenerate() JWK {
	key := JWK{}
	privateKey, err := loadPrivateKeyFromFile(keyFile)
	if err == nil {
		key.privateKey = privateKey
	} else if errors.Is(err, os.ErrNotExist) {
		privateKey, err := generatePrivateKey()
		if err != nil {
			panic(err)
		}
		key.privateKey = privateKey
		savePrivateKeyToFile(keyFile, privateKey)
	} else {
		panic(err)
	}
	return key
}
