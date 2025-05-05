package key

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func toJWTSigningMethod(method SignMethod) (jwt.SigningMethod, error) {
	mapping := map[SignMethod]jwt.SigningMethod{
		RS256: jwt.SigningMethodRS256,
		RS384: jwt.SigningMethodRS384,
		RS512: jwt.SigningMethodRS512,
		ES256: jwt.SigningMethodES256,
		ES384: jwt.SigningMethodES384,
		ES512: jwt.SigningMethodES512,
	}

	if alg, ok := mapping[method]; ok {
		return alg, nil
	}
	return nil, fmt.Errorf("invalid signing method: %s", method)
}
