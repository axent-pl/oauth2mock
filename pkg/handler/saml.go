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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/axent-pl/oauth2mock/pkg/claimservice"
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/di"
	"github.com/axent-pl/oauth2mock/pkg/errs"
	"github.com/axent-pl/oauth2mock/pkg/http/request"
	"github.com/axent-pl/oauth2mock/pkg/http/routing"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
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
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	XMLNSsamlp string   `xml:"xmlns:samlp,attr,omitempty"`
	XMLNSsaml  string   `xml:"xmlns:saml,attr,omitempty"`
	// XMLNSxsi     string   `xml:"xmlns:xsi,attr,omitempty"`
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	Destination  string `xml:"Destination,attr,omitempty"`
	InResponseTo string `xml:"InResponseTo,attr,omitempty"`

	Issuer    *SAMLIssuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer,omitempty"`
	Status    SAMLStatus     `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion *SAMLAssertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion,omitempty"`
}

type SAMLStatus struct {
	StatusCode SAMLStatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type SAMLStatusCode struct {
	Value string `xml:"Value,attr"`
}

/*** --- Assertion model --- ***/

type SAMLAssertion struct {
	XMLName            xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string                  `xml:"ID,attr"`
	Version            string                  `xml:"Version,attr"`
	IssueInstant       string                  `xml:"IssueInstant,attr"`
	Issuer             *SAMLIssuer             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject            *SAMLSubject            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject,omitempty"`
	Conditions         *SAMLConditions         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions,omitempty"`
	AuthnStatement     *SAMLAuthnStatement     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement,omitempty"`
	AttributeStatement *SAMLAttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement,omitempty"`
}

type SAMLSubject struct {
	NameID *SAMLNameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
}

type SAMLNameID struct {
	Format string `xml:"Format,attr,omitempty"`
	Value  string `xml:",chardata"`
}

type SAMLConditions struct {
	NotBefore           string                   `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter        string                   `xml:"NotOnOrAfter,attr,omitempty"`
	AudienceRestriction *SAMLAudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction,omitempty"`
}

type SAMLAudienceRestriction struct {
	Audience []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

type SAMLAuthnStatement struct {
	AuthnInstant string `xml:"AuthnInstant,attr"`
	SessionIndex string `xml:"SessionIndex,attr,omitempty"`
}

type SAMLAttributeStatement struct {
	Attributes []SAMLAttribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

type SAMLAttribute struct {
	Name         string               `xml:"Name,attr"`
	NameFormat   string               `xml:"NameFormat,attr,omitempty"`
	FriendlyName string               `xml:"FriendlyName,attr,omitempty"`
	Values       []SAMLAttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

type SAMLAttributeValue struct {
	// If you decide to emit xsi types, add: `xml:"xsi:type,attr,omitempty"` and set XMLNSxsi on the Response.
	// Type  string `xml:"xsi:type,attr,omitempty"`
	Value string `xml:",chardata"`
}

// SAMLHandler handles SAML authentication requests.
func SAMLHandler() routing.HandlerFunc {
	var wired bool
	var clientSrv clientservice.Service
	var claimSrv claimservice.Service

	clientSrv, wired = di.GiveMeInterface(clientSrv)
	if !wired {
		slog.Error("could not wire client service")
		return nil
	}

	claimSrv, wired = di.GiveMeInterface(claimSrv)
	if !wired {
		slog.Error("could not wire claim service")
		return nil
	}

	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("SAMLHandler started", "request", routing.RequestLogValue(r))

		// user
		user, ok := r.Context().Value(routing.CTX_USER).(userservice.Entity)
		if !ok {
			routing.WriteError(w, r, errs.New("unauthenticated", errs.ErrUnauthenticated).WithDetails("user not found in contextr"))
			return
		}

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

		client, err := clientSrv.GetClient(samlRequest.Issuer.Value)
		if err != nil {
			http.Error(w, "invalid issuer", http.StatusBadRequest)
			slog.Error("invalid client", "request", routing.RequestIDLogValue(r), "error", err)
			return
		}

		claims, err := claimSrv.GetUserClaims(user, client, []string{"saml"}, "saml")
		if err != nil {
			http.Error(w, "failed to get assertions", http.StatusInternalServerError)
			slog.Error("failed to get assertions", "request", routing.RequestIDLogValue(r), "error", err)
			return
		}

		now := time.Now().UTC()
		notBefore := now.Add(-1 * time.Minute)   // small clock skew
		notOnOrAfter := now.Add(5 * time.Minute) // short-lived demo assertion

		// Build AttributeStatement from claims (sub is used for NameID and not duplicated as Attribute)
		attrs := make([]SAMLAttribute, 0, len(claims))
		for k, v := range claims {
			if k == "sub" {
				continue
			}
			attr := SAMLAttribute{Name: k}
			switch vv := v.(type) {
			case string:
				attr.Values = []SAMLAttributeValue{{Value: vv}}
			case []string:
				for _, s := range vv {
					attr.Values = append(attr.Values, SAMLAttributeValue{Value: s})
				}
			case bool:
				if vv {
					attr.Values = []SAMLAttributeValue{{Value: "true"}}
				} else {
					attr.Values = []SAMLAttributeValue{{Value: "false"}}
				}
			case int, int32, int64, float32, float64:
				attr.Values = []SAMLAttributeValue{{Value: toString(v)}}
			default:
				// fallback to fmt-style string
				attr.Values = []SAMLAttributeValue{{Value: toString(v)}}
			}
			attrs = append(attrs, attr)
		}

		// Subject NameID from "sub" (fallback if missing)
		nameIDValue := "anonymous"
		if sub, ok := claims["sub"].(string); ok && sub != "" {
			nameIDValue = sub
		}

		// Audience: use the SP entityID (AuthnRequest Issuer) when present
		aud := ""
		if samlRequest.Issuer != nil && samlRequest.Issuer.Value != "" {
			aud = samlRequest.Issuer.Value
		}

		assertion := &SAMLAssertion{
			ID:           randomSAMLID(),
			Version:      "2.0",
			IssueInstant: now.Format(time.RFC3339),
			Issuer:       &SAMLIssuer{Value: "axent"},
			Subject: &SAMLSubject{
				NameID: &SAMLNameID{
					Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
					Value:  nameIDValue,
				},
			},
			Conditions: &SAMLConditions{
				NotBefore:    notBefore.Format(time.RFC3339),
				NotOnOrAfter: notOnOrAfter.Format(time.RFC3339),
			},
			AuthnStatement: &SAMLAuthnStatement{
				AuthnInstant: now.Format(time.RFC3339),
				SessionIndex: randomSAMLID(),
			},
			AttributeStatement: &SAMLAttributeStatement{
				Attributes: attrs,
			},
		}

		// Add AudienceRestriction if we have an audience
		if aud != "" {
			assertion.Conditions.AudienceRestriction = &SAMLAudienceRestriction{
				Audience: []string{aud},
			}
		}

		samlResponse := SAMLResponseDTO{
			XMLNSsamlp: "urn:oasis:names:tc:SAML:2.0:protocol",
			XMLNSsaml:  "urn:oasis:names:tc:SAML:2.0:assertion",
			// XMLNSxsi:     "http://www.w3.org/2001/XMLSchema-instance",
			ID:           randomSAMLID(),
			Version:      "2.0",
			IssueInstant: now.Format(time.RFC3339),
			Destination:  samlRequest.AssertionConsumerServiceURL,
			InResponseTo: samlRequest.ID,
			Issuer:       &SAMLIssuer{Value: "axent"},
			Status: SAMLStatus{
				StatusCode: SAMLStatusCode{
					Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
				},
			},
			Assertion: assertion,
		}

		samlResponseBytes, err := xml.Marshal(samlResponse)
		if err != nil {
			http.Error(w, "bad request", http.StatusInternalServerError)
			slog.Error("response marshaling failed", "request", routing.RequestIDLogValue(r), "error", err)
			return
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

// toString is a tiny helper to stringify interface values.
func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return fmtInt(int64(t))
	case int32:
		return fmtInt(int64(t))
	case int64:
		return fmtInt(t)
	case float32:
		return fmtFloat(float64(t))
	case float64:
		return fmtFloat(t)
	default:
		return fmtAny(t)
	}
}

func fmtInt(i int64) string     { return strconv.FormatInt(i, 10) }
func fmtFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }
func fmtAny(v any) string       { return fmt.Sprintf("%v", v) }
