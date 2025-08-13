package claimservice

import (
	"github.com/axent-pl/oauth2mock/pkg/clientservice"
	"github.com/axent-pl/oauth2mock/pkg/userservice"
)

type Service interface {
	GetUserClaims(user userservice.Entity, client clientservice.Entity, scope []string, purpose string) (map[string]interface{}, error)
	GetClientClaims(client clientservice.Entity, scope []string, purpose string) (map[string]interface{}, error)
}
