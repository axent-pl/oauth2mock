package claimservice

import (
	"github.com/axent-pl/oauth2mock/pkg/service/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/service/userservice"
)

type ClaimServicer interface {
	GetUserClaims(user userservice.UserHandler, client clientservice.ClientHandler, scope []string) (map[string]interface{}, error)
	GetClientClaims(client clientservice.ClientHandler, scope []string) (map[string]interface{}, error)
}
