package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/config"
)

type Settings struct {
	DataFile      string `env:"DATAFILE_PATH" default:"assets/config/config.json"`
	ServerAddress string `env:"SERVER_ADDRESS" default:":9090"`
	CaCertPath    string `env:"CA_CERT_PATH" default:"assets/key/cert.cert.rsa256.pem"`
	CaKeyPath     string `env:"CA_KEY_PATH" default:"assets/key/cert.key.rsa256.pem"`
}

var (
	settings        Settings
	caCert          *x509.Certificate
	caKey           *rsa.PrivateKey
	authHeaderValue string = "asd"
)

// Configure logger
func init() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	jsonLogger := slog.New(jsonHandler)
	slog.SetDefault(jsonLogger)
}

// Load config settings
func init() {
	err := config.Load(&settings)
	if err != nil {
		slog.Error("failed to load config settings", "error", err)
		os.Exit(1)
	}
	slog.Info("config settings initialized")
}

// Load ca certificate and key
func init() {
	slog.Info("loading CA cert and key from files", "certPath", settings.CaCertPath, "keyPath", settings.CaKeyPath)

	// certificate
	certPEM, err := os.ReadFile(settings.CaCertPath)
	if err != nil {
		slog.Error("failed to read CA cert PEM file", "error", err)
		os.Exit(1)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		err := errors.New("failed to decode PEM block containing certificate")
		slog.Error("failed to read CA cert PEM file", "error", err)
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		slog.Error("failed to parse CA cert from PEM file", "error", err)
		os.Exit(1)
	}
	caCert = cert

	// certificate private key
	keyPEM, err := os.ReadFile(settings.CaKeyPath)
	if err != nil {
		slog.Error("failed to read CA key PEM file", "error", err)
		os.Exit(1)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		err := errors.New("failed to decode PEM block containing private key")
		slog.Error("failed to read CA key PEM file", "error", err)
		os.Exit(1)
	}
	priv, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		slog.Error("failed to parse CA key from PEM file", "error", err)
		os.Exit(1)
	}
	caKey = priv
}

func main() {
	server := &http.Server{
		Addr:    settings.ServerAddress,
		Handler: http.HandlerFunc(handleProxy),
	}
	server.ListenAndServe()
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Acknowledge CONNECT
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Generate certificate for the requested host
	cert, err := generateCertForHost(r.Host)
	if err != nil {
		slog.Error("failed to generate certificate for host", "error", err)
		clientConn.Close()
		return
	}

	// Start TLS with the client
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*cert}}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		slog.Error("failed TLS handshake", "error", err)
		tlsClientConn.Close()
		return
	}

	// Read the TLS-wrapped request
	req, err := http.ReadRequest(bufio.NewReader(tlsClientConn))
	if err != nil {
		slog.Error("failed reading HTTPS request", "error", err)
		tlsClientConn.Close()
		return
	}

	// Create new HTTPS request to real server
	req.URL.Scheme = "https"
	req.URL.Host = r.Host
	req.RequestURI = ""
	for name, values := range r.Header {
		if strings.ToLower(name) == "authorization" {
			continue
		}
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	req.Header.Set("Authorization", authHeaderValue)

	// Create HTTPS client to forward request
	tlsTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Trust all certs (unsafe, OK for MITM)
	}
	resp, err := tlsTransport.RoundTrip(req)
	if err != nil {
		// http.Error(tlsClientConn, "Request failed: "+err.Error(), http.StatusBadGateway)
		tlsClientConn.Close()
		return
	}
	defer resp.Body.Close()

	// Write back response
	err = resp.Write(tlsClientConn)
	if err != nil {
		slog.Error("failed writing response to client:", "error", err)
	}
	tlsClientConn.Close()
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	for name, values := range r.Header {
		if strings.ToLower(name) == "authorization" {
			continue
		}
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	req.Header.Set("Authorization", authHeaderValue)

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, "Request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

}

func generateCertForHost(host string) (*tls.Certificate, error) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:              []string{host},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPem, keyPem)
	return &cert, err
}
