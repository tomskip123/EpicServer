package auth

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/oauth2"
)

// AuthConfigFromEnv builds an oauth2.Config using environment variables.
// Required variables (with prefix, default EPIC_AUTH):
//   - <PREFIX>_CLIENT_ID
//   - <PREFIX>_CLIENT_SECRET
//
// And either:
//   - <PREFIX>_PROVIDER (github, gitlab, google, microsoft)
//   - or <PREFIX>_AUTH_URL and <PREFIX>_TOKEN_URL
//
// Optional variables:
//   - <PREFIX>_REDIRECT_URL
//   - <PREFIX>_SCOPES (comma or space separated)
func AuthConfigFromEnv(prefix string) (*oauth2.Config, error) {
	if prefix == "" {
		prefix = "EPIC_AUTH"
	}
	prefix = strings.TrimSuffix(prefix, "_")
	prefix = strings.ToUpper(prefix)

	lookupRequired := func(suffix string) (string, error) {
		value, ok := os.LookupEnv(prefix + "_" + suffix)
		if !ok {
			return "", fmt.Errorf("%s_%s is required", prefix, suffix)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf("%s_%s is required", prefix, suffix)
		}
		return value, nil
	}

	lookupOptional := func(suffix string) string {
		value, ok := os.LookupEnv(prefix + "_" + suffix)
		if !ok {
			return ""
		}
		return strings.TrimSpace(value)
	}

	clientID, err := lookupRequired("CLIENT_ID")
	if err != nil {
		return nil, err
	}
	clientSecret, err := lookupRequired("CLIENT_SECRET")
	if err != nil {
		return nil, err
	}

	authURL := lookupOptional("AUTH_URL")
	tokenURL := lookupOptional("TOKEN_URL")
	provider := strings.ToLower(lookupOptional("PROVIDER"))
	resolvedProvider := ""

	var endpoint oauth2.Endpoint
	switch {
	case authURL != "" || tokenURL != "":
		if authURL == "" || tokenURL == "" {
			return nil, fmt.Errorf("%s_AUTH_URL and %s_TOKEN_URL must both be set", prefix, prefix)
		}
		endpoint = oauth2.Endpoint{AuthURL: authURL, TokenURL: tokenURL}
	case provider != "":
		ep, ok := wellKnownProviderEndpoints[provider]
		if !ok {
			return nil, fmt.Errorf("unknown auth provider %q", provider)
		}
		resolvedProvider = provider
		endpoint = ep
	default:
		return nil, fmt.Errorf("set %s_PROVIDER or provide both %s_AUTH_URL and %s_TOKEN_URL", prefix, prefix, prefix)
	}

	redirectURL := lookupOptional("REDIRECT_URL")
	scopesValue := lookupOptional("SCOPES")

	var scopes []string
	if scopesValue != "" {
		for _, part := range strings.FieldsFunc(scopesValue, func(r rune) bool {
			return r == ',' || r == ' '
		}) {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				scopes = append(scopes, trimmed)
			}
		}
	} else if resolvedProvider != "" {
		scopes = append(scopes, wellKnownProviderScopes[resolvedProvider]...)
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     endpoint,
		Scopes:       scopes,
	}, nil
}
