package claims

import (
	"encoding/json"
	"fmt"
	"os"
)

const claimsFile = "run/claims.json"

func GetClaims(subject string, client string) (map[string]interface{}, error) {
	// Read the JSON file
	data, err := os.ReadFile(claimsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read claims file: %w", err)
	}

	// Parse the JSON into a map
	var claimsData map[string]map[string]interface{}
	err = json.Unmarshal(data, &claimsData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims JSON: %w", err)
	}

	// Find claims for the subject
	subjectClaims, ok := claimsData[subject]
	if !ok {
		return nil, fmt.Errorf("subject %s not found", subject)
	}

	// Extract base claims
	baseClaims, ok := subjectClaims["base"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("base claims for subject %s are missing or invalid", subject)
	}

	// Start with base claims
	finalClaims := make(map[string]interface{})
	for k, v := range baseClaims {
		finalClaims[k] = v
	}

	// Apply overrides for the client if available
	if client != "" {
		overrideSection, hasOverrides := subjectClaims["override"].(map[string]interface{})
		if hasOverrides {
			clientOverrides, hasClient := overrideSection[client].(map[string]interface{})
			if hasClient {
				for k, v := range clientOverrides {
					finalClaims[k] = v
				}
			}
		}
	}

	return finalClaims, nil
}
