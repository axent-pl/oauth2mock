package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type ClaimServicer interface {
	GetClaims(subject Subject, client Client) (map[string]interface{}, error)
}

type claimDetails struct {
	Base      map[string]interface{}
	Overrides map[string]map[string]interface{}
}

type claimService struct {
	claims map[string]claimDetails
}

func NewClaimService(claimsJSONFilepath string) (ClaimServicer, error) {
	file, err := os.Open(claimsJSONFilepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open claims config file: %w", err)
	}
	defer file.Close()
	return newClaimSimpleStorerFromReader(file)
}

func newClaimSimpleStorerFromReader(reader io.Reader) (*claimService, error) {
	var rawData struct {
		Users map[string]struct {
			Claims struct {
				Base      map[string]interface{}            `json:"base"`
				Overrides map[string]map[string]interface{} `json:"override"`
			} `json:"claims"`
		} `json:"users"`
	}

	if err := json.NewDecoder(reader).Decode(&rawData); err != nil {
		return nil, fmt.Errorf("failed to parse claims config file: %w", err)
	}

	claims := make(map[string]claimDetails)
	for username, user := range rawData.Users {
		claims[username] = claimDetails{
			Base:      user.Claims.Base,
			Overrides: user.Claims.Overrides,
		}
	}

	return &claimService{claims: claims}, nil
}

func (s *claimService) GetClaims(subject Subject, client Client) (map[string]interface{}, error) {
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
