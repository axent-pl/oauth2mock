# OAuth2Mock (Axes) 🔐

> "Because sometimes Keycloak is just too much for your morning coffee development session."

OAuth2Mock (codename Axes) is your friendly neighborhood OAuth2 authorization server. It's designed to replace heavyweight authentication servers during local development, without the memory footprint that makes your laptop sound like a rocket ship.

**🚨 Important:** This is a development tool. Please don't use it in production unless you enjoy exciting security incidents!

## ✨ Why Axes?

* **Feather-light:** Uses less memory than your average cat GIF
* **Lightning-fast:** Starts faster than you can say "Keycloak initialization"
* **Zero-click config:** JSON files and env vars - because life's too short for web GUIs
* **Dev-friendly:** Run it as a Go app or containerize it - we don't judge

## 🚀 Quick Start

### For Go Developers
```sh
make run    # That's it. Really.
```

### For Docker Enthusiasts
```sh
docker run -p 8222:8222 prond/axes:nightly    # Easy peasy! 🐳
```

## 📊 The Numbers Don't Lie

Check out this David vs. Goliath comparison (Axes vs Keycloak):

```console
CONTAINER ID   NAME         CPU %     MEM USAGE / LIMIT     MEM %     NET I/O          BLOCK I/O        PIDS
294f9c29f74f   axes-1       0.00%     5.246MiB / 7.654GiB   0.07%     10kB / 12.4kB    0B / 0B          8
07a88b8c0903   keycloak-1   1.55%     621.4MiB / 7.654GiB   7.93%     21.9kB / 921kB   78.4MB / 181MB   53
```

Spot the difference? That's right - Axes is like a tiny espresso shot compared to Keycloak's grande frappuccino! 

## 🔧 Configuration

### Environment Variables

| ENV | Default | What's this? |
|-----|---------|-------------|
| `DATAFILE_PATH` | assets/config/config.json | Your configuration JSON file |
| `SERVER_ADDRESS` | :8222 | Where the magic happens |
| `TEMPLATES_PATH` | assets/template | HTML templates location |
| `OAUTH2_ISSUER` | empty | Your issuer URL (optional) |
| `OAUTH2_ISSUER_FROM_ORIGIN` | TRUE | Auto-magic issuer detection |

### OpenID Connect Configuration

When running locally (with `OAUTH2_ISSUER=http://localhost:8222` or `OAUTH2_ISSUER_FROM_ORIGIN=TRUE`), you'll get this tasty OIDC config:

```json
{
    "issuer": "http://localhost:8222",
    "authorization_endpoint": "http://localhost:8222/authorize",
    "token_endpoint": "http://localhost:8222/token",
    "jwks_uri": "http://localhost:8222/.well-known/jwks.json",
    "grant_types_supported": ["authorization_code", "client_credentials", "password"],
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "userinfo_endpoint": "",
    "response_modes_supported": null
}
```

### JSON Configuration

Place this in your `DATAFILE_PATH` to define users and clients:

```json
{
    "signing": {
        "keys": [
            {
                "provider": {
                    "fromPEM": {
                        "path": "assets/key/key.rsa256.pem"
                    }
                },
                "method": "RS256",
                "active": false
            },
            {
                "provider": {
                    "fromRandom": {
                        "type": "P-256",
                        "deterministic": true,
                        "seed": "abc"
                    }
                },
                "method": "ES256",
                "active": true
            },
            {
                "provider": {
                    "fromCertPEM": {
                        "keyPath": "assets/key/cert.key.rsa512.pem",
                        "certPath": "assets/key/cert.cert.rsa512.pem"
                    }
                },
                "method": "RS256",
                "active": false
            }
        ]
    },
    "users": {
        "provider": "json",
        "users": {
            "demo": {
                "username": "demo",
                "password": "demo",
                "claims": {
                    "default" : {
                        "base": {
                            "preferred_username": "John.Demo@acme.com",
                            "realm_roles": [
                                "DEMO"
                            ]
                        },
                        "scopeOverrides": {
                            "email": {
                                "email": "John.Demo@acme.com"
                            },
                            "products::read": {
                                "products": ["A", "B"]
                            }
                        }
                    }
                },
                "consents": {
                    "openid": true,
                    "profile": true,
                    "email": true,
                    "products::read": false
                }
            },
            "admin": {
                "username": "admin",
                "password": "admin",
                "claims": {
                    "default": {
                        "base": {
                            "preferred_username": "John.Demo@acme.com",
                            "realm_roles": [
                                "ADMIN"
                            ]
                        },
                        "clientOverrides": {
                            "ACME": {
                                "client_roles": [
                                    "DEMO",
                                    "ADMIN"
                                ]
                            }
                        },
                        "scopeOverrides": {
                            "email": {
                                "email": "John.Demo@acme.com"
                            },
                            "products::read": {
                                "products": ["A", "B","C"]
                            }
                        }
                    }
                },
                "consents": {
                    "profile": true,
                    "email": true,
                    "products::read": true
                }
            }
        }
    },
    "claims": {
        "provider": "json"
    },
    "clients": {
        "ACME": {
            "client_id": "ACME",
            "client_secret": "acme-secret",
            "redirect_uri": "http*//localhost*",
            "claims": {
                "default": {
                    "azp": "ACME"
                }
            }
        }
    },
    "consents": {
        "provider": "json",
        "scopes": {
            "openid": { "requireConsent": false },
            "profile": { "requireConsent": false },
            "email": { "requireConsent": true },
            "products::read": { "requireConsent": true },
            "avatar": { "requireConsent": false }
        }
    },
    "authorization": {
        "provider": "memory",
        "authorizationCodeLength": 16,
        "authorizationRequestTTLSeconds": 60
    },
    "session": {
        "provider": "memory",
        "config": {
            "ttlSeconds": 60
        }
    }
}
```

## 🎯 Pro Tips

* **For Junior Devs:** Start with the default config and modify gradually
* **For Mid-level Devs:** Check out the claim overrides for advanced user configuration
* **For Senior Devs:** Yes, you can automate the config generation. We trust you!

## ⚠️ Final Words of Wisdom

Remember: Axes is like a practice sword - perfect for training, but don't bring it to a real battle. It's missing production-grade security features by design, keeping it light and simple for development purposes.

## 🤝 Contributing

Found a bug? Want to add a feature? PRs are welcome! Just remember our motto: "Keep it simple, keep it light!"

---
Made with ❤️ by developers who got tired of waiting for Keycloak to start