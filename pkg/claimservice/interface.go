package claimservice

import (
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/consentservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type ClaimServicer interface {
	GetUserClaims(user userservice.UserHandler, client clientservice.ClientHandler, consentservice consentservice.ConsentServicer, scope []string) (map[string]interface{}, error)
	GetClientClaims(client clientservice.ClientHandler, scope []string) (map[string]interface{}, error)
}
