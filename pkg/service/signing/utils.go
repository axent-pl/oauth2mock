package signing

import (
	"fmt"

	"slices"

	"github.com/golang-jwt/jwt/v5"
)

func toJWTSigningMethod(method SigningMethod) (jwt.SigningMethod, error) {
	mapping := map[SigningMethod]jwt.SigningMethod{
		RS256: jwt.SigningMethodRS256,
		RS384: jwt.SigningMethodRS384,
		RS512: jwt.SigningMethodRS512,
		ES256: jwt.SigningMethodES256,
		ES384: jwt.SigningMethodES384,
		ES512: jwt.SigningMethodES512,
		PS256: jwt.SigningMethodPS256,
		PS384: jwt.SigningMethodPS384,
		PS512: jwt.SigningMethodPS512,
	}

	if alg, ok := mapping[method]; ok {
		return alg, nil
	}
	return nil, fmt.Errorf("invalid signing method: %s", method)
}

func IsKeyCompatible(method SigningMethod, keyType KeyType) bool {
	validKeys, ok := SigningMethodKeyTypeCompatibility[method]
	if !ok {
		return false
	}
	return slices.Contains(validKeys, keyType)
}
