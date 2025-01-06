# oauth2mock

## Calims

```json
{
    "username1": {
        "type": "user",
        "base": {
            "sub": "John",
            "preffered_username": "John.Doe@acme.com",
            "realm_roles": [
                "SUPERADMIN"
            ]
        },
        "override": {
            "clientA": {
                "client_roles": [
                    "ADMIN"
                ]
            }
        }
    },
    "clientB": {
        "type": "client",
        "base": {
            "sub": "applicationB"
        },
        "override": {
            "clientA": {
                "client_roles": [
                    "READER"
                ]
            }
        }
    }
}
```