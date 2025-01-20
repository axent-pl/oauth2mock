# OAuth2Mock

OAuth2Mock (code name Axes) is a lightweight OAuth2 authorization server designed to replace resource-intensive servers like Keycloak during local development. This tool is **not intended for production environments**.

## Features
* Lightweight and minimal resource usage.
* Provides OpenID Connect (OIDC) endpoints for local development.
* Configurable via environment variables and JSON files.
* Runs as a Go application or a Docker container.

## How to run

### From Source
Run the server using the make command:
```sh
make run
```

### Using Docker
Run the prebuilt Docker image from Docker Hub:
```sh
docker run -p 8080:8080 prond/axes:nightly
```

## Axes vs Keycloak: resource consuption

Below is a comparison of resource usage between Axes and Keycloak, captured after Keycloak completed initialization (memory peaked over 1 GiB and CPU usage reached 199%).

```console
> docker stats

CONTAINER ID   NAME         CPU %     MEM USAGE / LIMIT     MEM %     NET I/O          BLOCK I/O        PIDS
294f9c29f74f   axes-1       0.00%     5.246MiB / 7.654GiB   0.07%     10kB / 12.4kB    0B / 0B          8
07a88b8c0903   keycloak-1   1.55%     621.4MiB / 7.654GiB   7.93%     21.9kB / 921kB   78.4MB / 181MB   53
```

Axes is significantly more resource-efficient, making it an ideal choice for local development environments.

## OpenID Configuration

If `OAUTH2_ISSUER=http://localhost:8080` or `OAUTH2_ISSUER_FROM_ORIGIN=TRUE` is set, and the server is listening on port 8080 on localhost, the OpenID configuration will look like this:
```json
{
    "issuer": "http://localhost:8080",
    "authorization_endpoint": "http://localhost:8080/authorize",
    "token_endpoint": "http://localhost:8080/token",
    "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
    "grant_types_supported": ["authorization_code", "client_credentials", "password"],
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "userinfo_endpoint": "",
    "response_modes_supported": null
}
```

## Settings
| ENV | Default | Description |
|-----|---------|-------------|
| **KEY_PATH** | data/key.pem | Path to the RSA private key file. |
| **DATAFILE_PATH** | data/config.json | Path to the JSON configuration file. |
| **SERVER_ADDRESS** | :8080 | The address on which the server will listen |
| **TEMPLATES_PATH** | data | Path to the directory containing HTML templates. |
| **OAUTH2_ISSUER** |   | URL of the issuer. If not set and OAUTH2_ISSUER_FROM_ORIGIN=TRUE, it will be populated dynamically. |
| **OAUTH2_ISSUER_FROM_ORIGIN** | TRUE | If TRUE, the issuer will be populated dynamically based on the request origin. |

## Configuration
Below is an example JSON configuration file which needs to be in `DATAFILE_PATH`.
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
                    "realm_roles": ["DEMO"]
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
                    "realm_roles": ["ADMIN"]
                },
                "clientOverrides": {
                    "ACME": {
                        "client_roles": ["DEMO","ADMIN"]
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

## Notes
* **Axes** is designed to mimic basic OAuth2/OpenID Connect functionality for local testing and development.
* The tool provides a lightweight alternative to Keycloak for scenarios where resource efficiency and simplicity are priorities.
* **Not for production**: This server lacks the robustness and security features required for production deployments.