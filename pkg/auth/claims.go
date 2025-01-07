package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

type ClaimStorer interface {
	GetClaims(subject Subject, client Client) (map[string]interface{}, error)
}

type ClaimSimpleStorerClaims struct {
	Base      map[string]interface{}
	Overrides map[string]map[string]interface{}
}

type ClaimSimpleStorer struct {
	claims map[string]ClaimSimpleStorerClaims
}

func NewClaimSimpleStorer(claimsJSONFilepath string) *ClaimSimpleStorer {
	type jsonUserClaimsStruct struct {
		Base      map[string]interface{}            `json:"base"`
		Overrides map[string]map[string]interface{} `json:"override"`
	}
	type jsonUserStruct struct {
		Username string               `json:"username"`
		Password string               `json:"password"`
		Claims   jsonUserClaimsStruct `json:"claims"`
	}
	type jsonStoreStruct struct {
		Users map[string]jsonUserStruct `json:"users"`
	}

	f := jsonStoreStruct{}

	data, err := os.ReadFile(claimsJSONFilepath)
	if err != nil {
		panic(fmt.Errorf("failed to read claims config file: %w", err))
	}

	if err := json.Unmarshal(data, &f); err != nil {
		panic(fmt.Errorf("failed to parse claims config file: %w", err))
	}

	cs := ClaimSimpleStorer{
		claims: make(map[string]ClaimSimpleStorerClaims),
	}

	for key, user := range f.Users {
		cs.claims[key] = ClaimSimpleStorerClaims{
			Base:      user.Claims.Base,
			Overrides: user.Claims.Overrides,
		}
	}

	return &cs
}

func (s *ClaimSimpleStorer) GetClaims(subject Subject, client Client) (map[string]interface{}, error) {
	claims := make(map[string]interface{})

	subjectClaims, ok := s.claims[subject.Name]
	if !ok {
		return claims, fmt.Errorf("no claims for subject %s", subject.Name)
	}

	for c, v := range subjectClaims.Base {
		claims[c] = v
	}
	clientOverrides, ok := subjectClaims.Overrides[client.Id]
	if ok {
		for c, v := range clientOverrides {
			claims[c] = v
		}
	}

	return claims, nil
}
