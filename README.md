# OAuth2Mock

This project serves a purpose to replace Keycloak (or other resource hungry authorization servers) during local development.
It is **NOT** meant for production applications.

## How to run

Plain go run from sources
```sh
make run
```

Container from a dockerhub image
```sh
docker run -p 8080:8080 prond/axes:nightly
```

## Axes vs Keycloak

This a simple comparison of resource consuption by Keycloak and Axes (a snapshot of the docker stats after Keycloak has done all the initialization when memory usage went over 1GiB and CPU to 199%  ).

```console
> docker stats

CONTAINER ID   NAME         CPU %     MEM USAGE / LIMIT     MEM %     NET I/O          BLOCK I/O        PIDS
294f9c29f74f   axes-1       0.00%     5.246MiB / 7.654GiB   0.07%     10kB / 12.4kB    0B / 0B          8
07a88b8c0903   keycloak-1   1.55%     621.4MiB / 7.654GiB   7.93%     21.9kB / 921kB   78.4MB / 181MB   53
```

## OpenID Configuration

Given that `OAUTH2_ISSUER=http://localhost:8080` or `OAUTH2_ISSUER_FROM_ORIGIN=TRUE` and server is listening on `8080` on `localhost` the OpenID Configuration looks like follows.
```json
{
    "issuer": "http://localhost:8080",
    "authorization_endpoint": "http://localhost:8080/authorize",
    "token_endpoint": "http://localhost:8080/token",
    "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
    "grant_types_supported": [
        "authorization_code",
        "client_credentials"
    ],
    "response_types_supported": [
        "code"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "userinfo_endpoint": "",
    "response_modes_supported": null
}
```

## Settings
| ENV | Default | Description |
|-----|---------|-------------|
| **KEY_PATH** | data/key.pem | Path to the RSA private key file |
| **DATAFILE_PATH** | data/config.json | Path to the JSON file with configuration |
| **SERVER_ADDRESS** | :8080 | The address on which the server will listen |
| **TEMPLATES_PATH** | data | Path to the directory with HTML templates |
| **OAUTH2_ISSUER** |   | The URL of the Issuer. If not set and the OAUTH2_ISSUER_FROM_ORIGIN=TRUE it will be populated with the ORIGIN of the request |
| **OAUTH2_ISSUER_FROM_ORIGIN** | TRUE | If TRUE the Issuer will be populated with the ORIGIN of the request |

## Configuration
```json
{
    "users" : {
        "demo" : {
            "username": "demo",
            "password": "demo",
            "claims" : {
                "base": {
                    "sub": "Demo",
                    "preferred_username": "John.Demo@acme.com",
                    "realm_roles": [
                        "DEMO"
                    ]
                }
            }
        },
        "admin" : {
            "username": "admin",
            "password": "admin",
            "claims" : {
                "base": {
                    "sub": "Demo",
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
                    }
                }
            }
        }
    },
    "clients" : {
        "ACME" : {
            "client_id": "ACME",
            "client_secret": "acme-secret",
            "redirect_uri": "http*//localhost*",
            "claims": {
                "azp": "ACME"
            }
        }
    }
}
```