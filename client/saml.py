#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import datetime as dt
import os
import urllib.parse
import uuid
import zlib
import xml.etree.ElementTree as ET

# If you don't want to use 'requests', you can replace the HTTP calls
# with urllib (see notes below).
import requests  # pip install requests (widely available)

IDP_SSO_URL = os.getenv("IDP_SSO_URL", "http://localhost:8222/saml")  # IdP SSO endpoint
SP_ENTITY_ID = os.getenv("SP_ENTITY_ID", "ACME")            # Your SP entityID
ACS_URL = os.getenv("ACS_URL", "http://localhost:1234/acs")           # Your Assertion Consumer Service URL
RELAY_STATE = os.getenv("RELAY_STATE", "opaque-relay-state")
BINDING = os.getenv("BINDING", "redirect").lower()                    # 'redirect' or 'post'

SAML2P = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML2 = "urn:oasis:names:tc:SAML:2.0:assertion"
ET.register_namespace("samlp", SAML2P)
ET.register_namespace("saml", SAML2)

def _isoformat_z(dt_utc: dt.datetime) -> str:
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

def build_authn_request_xml(
    issuer: str,
    acs_url: str,
    destination: str,
    force_authn: bool = False,
    is_passive: bool = False,
    nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    protocol_binding: str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
) -> bytes:
    """
    Build a minimal SAML 2.0 AuthnRequest (unsigned).
    """
    now = dt.datetime.utcnow()
    req_id = "_" + uuid.uuid4().hex

    attrs = {
        "ID": req_id,
        "Version": "2.0",
        "IssueInstant": _isoformat_z(now),
        "Destination": destination,
        "ProtocolBinding": protocol_binding,
        "AssertionConsumerServiceURL": acs_url,
    }
    if force_authn:
        attrs["ForceAuthn"] = "true"
    if is_passive:
        attrs["IsPassive"] = "true"

    root = ET.Element(f"{{{SAML2P}}}AuthnRequest", attrs)

    issuer_el = ET.SubElement(root, f"{{{SAML2}}}Issuer")
    issuer_el.text = issuer

    # Optional: request a NameID format
    ET.SubElement(
        root,
        f"{{{SAML2P}}}NameIDPolicy",
        {
            "Format": nameid_format,
            "AllowCreate": "true",
        },
    )

    # Optional: AuthnContext (password over TLS typical)
    rac = ET.SubElement(
        root,
        f"{{{SAML2P}}}RequestedAuthnContext",
        {"Comparison": "exact"},
    )
    ET.SubElement(
        rac,
        f"{{{SAML2}}}AuthnContextClassRef",
    ).text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # Serialize with XML declaration
    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True, method="xml")
    return xml_bytes

def to_redirect_binding_param(xml_bytes: bytes) -> str:
    """
    Per SAML Bindings spec (HTTP-Redirect): DEFLATE (raw), Base64, then URL-encode.
    """
    # raw DEFLATE (wbits=-15)
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(xml_bytes) + compressor.flush()
    b64 = base64.b64encode(deflated)  # bytes
    return b64.decode("ascii")

def to_post_binding_param(xml_bytes: bytes) -> str:
    """Base64 of the raw XML for HTTP-POST binding."""
    return base64.b64encode(xml_bytes).decode("ascii")

def build_redirect_url(idp_sso_url: str, saml_request_b64: str, relay_state: str = None) -> str:
    params = [("SAMLRequest", saml_request_b64)]
    if relay_state is not None:
        params.append(("RelayState", relay_state))
    # Note: No Signature here (unsigned). To sign, you'd add SigAlg and Signature per spec.
    query = urllib.parse.urlencode(params)
    sep = "&" if ("?" in idp_sso_url) else "?"
    return f"{idp_sso_url}{sep}{query}"

def send_redirect(idp_sso_url: str, saml_request_b64: str, relay_state: str = None):
    """
    For non-browser flows (testing), we can trigger the redirect as an HTTP GET.
    In a real browser flow, you'd just 302-redirect the user-agent to this URL.
    """
    url = build_redirect_url(idp_sso_url, saml_request_b64, relay_state)
    print("Redirect URL:\n", url)
    # Test the endpoint (optional):
    try:
        r = requests.get(url, allow_redirects=False, timeout=5)
        print("GET status:", r.status_code)
        print("GET headers:", dict(r.headers))
        # Body may be HTML/redirect; printing can be noisy
    except Exception as e:
        print("GET failed:", e)

def send_post(idp_sso_url: str, saml_request_b64: str, relay_state: str = None):
    """
    Pure back-channel POST for testing. In a browser flow, you'd render a form:
    <form method="post" action="..."><input name="SAMLRequest" value="..."/></form>
    """
    data = {"SAMLRequest": saml_request_b64}
    if relay_state is not None:
        data["RelayState"] = relay_state
    print("POSTing to:", idp_sso_url)
    try:
        r = requests.post(idp_sso_url, data=data, timeout=5)
        print("POST status:", r.status_code)
        # The IdP might return HTML; be cautious printing entire r.text.
        print("Response (first 500 chars):\n", r.text[:500])
    except Exception as e:
        print("POST failed:", e)

def main():
    xml_bytes = build_authn_request_xml(
        issuer=SP_ENTITY_ID,
        acs_url=ACS_URL,
        destination=IDP_SSO_URL,
        force_authn=False,
        is_passive=False,
        nameid_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        protocol_binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",  # how you want the IdP to post back to your ACS
    )

    print("AuthnRequest XML:\n", xml_bytes.decode("utf-8"))

    if BINDING == "redirect":
        saml_request_b64 = to_redirect_binding_param(xml_bytes)
        send_redirect(IDP_SSO_URL, saml_request_b64, RELAY_STATE)
    elif BINDING == "post":
        saml_request_b64 = to_post_binding_param(xml_bytes)
        send_post(IDP_SSO_URL, saml_request_b64, RELAY_STATE)
    else:
        raise SystemExit("Unknown BINDING. Use 'redirect' or 'post'.")

if __name__ == "__main__":
    main()