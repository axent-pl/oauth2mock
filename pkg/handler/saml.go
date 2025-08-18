package handler

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/http/request"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
)

type SAMLRequestDTO struct {
	SAMLRequest string `form:"SAMLRequest" queryParam:"SAMLRequest"`
	RelayState  string `form:"RelayState" queryParam:"RelayState"`
	SigAlg      string `form:"SigAlg" queryParam:"SigAlg"`
	Signature   string `form:"Signature" queryParam:"Signature"`
}

type SAMLAuthnRequest struct {
	XMLName                     xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string            `xml:"ID,attr"`
	Version                     string            `xml:"Version,attr"`
	IssueInstant                string            `xml:"IssueInstant,attr"`
	Destination                 string            `xml:"Destination,attr,omitempty"`
	AssertionConsumerServiceURL string            `xml:"AssertionConsumerServiceURL,attr,omitempty"`
	ProtocolBinding             string            `xml:"ProtocolBinding,attr,omitempty"`
	ForceAuthn                  *bool             `xml:"ForceAuthn,attr,omitempty"`
	IsPassive                   *bool             `xml:"IsPassive,attr,omitempty"`
	Issuer                      *SAMLIssuer       `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	NameIDPolicy                *SAMLNameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy,omitempty"`
}

type SAMLIssuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

type SAMLNameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format      string   `xml:"Format,attr,omitempty"`
	AllowCreate *bool    `xml:"AllowCreate,attr,omitempty"`
}

type SAMLResponseDTO struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	XMLNSsamlp   string   `xml:"xmlns:samlp,attr,omitempty"`
	XMLNSsaml    string   `xml:"xmlns:saml,attr,omitempty"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr,omitempty"`
	InResponseTo string   `xml:"InResponseTo,attr,omitempty"`

	Issuer *SAMLIssuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	Status SAMLStatus  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

	// You can add Assertion later if needed.
}

type SAMLStatus struct {
	StatusCode SAMLStatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type SAMLStatusCode struct {
	Value string `xml:"Value,attr"`
}

// SAMLHandler handles SAML authentication requests.
func SAMLHandler() routing.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("SAMLHandler started", "request", routing.RequestLogValue(r))

		requstDTO := &SAMLRequestDTO{}
		if valid, requestValidator := request.UnmarshalAndValidate(r, requstDTO); !valid {
			http.Error(w, "bad request", http.StatusBadRequest)
			slog.Error("request validation failed", "request", routing.RequestIDLogValue(r), "validationErrors", requestValidator.Errors)
			return
		}

		samlRequest, _, err := ParseSAMLRequest(requstDTO.SAMLRequest)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			slog.Error("request unmarshaling failed", "request", routing.RequestIDLogValue(r), "error", err)
			return
		}

		samlResponse := SAMLResponseDTO{
			XMLNSsamlp:   "urn:oasis:names:tc:SAML:2.0:protocol",
			XMLNSsaml:    "urn:oasis:names:tc:SAML:2.0:assertion",
			ID:           randomSAMLID(),
			Version:      "2.0",
			IssueInstant: time.Now().UTC().Format(time.RFC3339),
			Destination:  samlRequest.AssertionConsumerServiceURL,
			InResponseTo: samlRequest.ID,
			Issuer:       &SAMLIssuer{Value: "axent"},
			Status: SAMLStatus{
				StatusCode: SAMLStatusCode{
					Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
				},
			},
		}
		samlResponseBytes, err := xml.Marshal(samlResponse)
		if err != nil {
			http.Error(w, "bad request", http.StatusInternalServerError)
			slog.Error("response marshaling failed", "request", routing.RequestIDLogValue(r), "error", err)
		}
		samlResponseString := base64.StdEncoding.EncodeToString(samlResponseBytes)

		redirectURL, err := url.Parse(samlRequest.AssertionConsumerServiceURL)
		if err != nil {
			http.Error(w, "invalid ACSUrl", http.StatusBadRequest)
			slog.Error("Invalid ACSUrl", "error", err)
			return
		}
		q := redirectURL.Query()
		q.Set("SAMLResponse", samlResponseString)
		if requstDTO.RelayState != "" {
			q.Set("RelayState", requstDTO.RelayState)
		}
		redirectURL.RawQuery = q.Encode()

		slog.Info("SAMLHandler redirecting", "redirectURL", redirectURL.String())
		http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
	}
}

func ParseSAMLRequest(enc string) (*SAMLAuthnRequest, []byte, error) {
	slog.Info(enc)
	// 1) Base64 decode
	compressed, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		// Try URL-safe alphabet just in case
		compressed, err = base64.URLEncoding.DecodeString(enc)
		if err != nil {
			return nil, nil, errors.New("invalid base64 in SAMLRequest")
		}
	}

	// 2) Inflate (Redirect binding uses raw DEFLATE; some stacks use zlib wrapper)
	xmlBytes, inflateErr := inflateRawDeflate(compressed)
	if inflateErr != nil {
		// fallback to zlib (RFC1950)
		if xmlBytes, err = inflateZlib(compressed); err != nil {
			// If both fail, it might be POST binding (no compression) — accept as-is if it looks like XML
			if looksLikeXML(compressed) {
				xmlBytes = compressed
			} else {
				return nil, nil, errors.New("unable to inflate SAMLRequest (tried DEFLATE and zlib)")
			}
		}
	}

	// 3) Unmarshal XML
	var req SAMLAuthnRequest
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		return nil, nil, err
	}
	return &req, xmlBytes, nil
}

func inflateRawDeflate(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	return io.ReadAll(r)
}

func inflateZlib(b []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func looksLikeXML(b []byte) bool {
	// Trim a tiny bit of whitespace and check for '<'
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	return i < len(b) && b[i] == '<'
}

func randomSAMLID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "_" + hex.EncodeToString(b[:])
}
