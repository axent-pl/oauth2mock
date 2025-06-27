package clientservice

import (
	"regexp"
	"strings"
)

func MatchesWildcard(redirectURI, clientRedirectURI string) bool {
	escapedPattern := regexp.QuoteMeta(clientRedirectURI)
	regexPattern := strings.ReplaceAll(escapedPattern, "\\*", ".*")
	regex, err := regexp.Compile("^" + regexPattern + "$")
	if err != nil {
		return false
	}
	return regex.MatchString(redirectURI)
}
