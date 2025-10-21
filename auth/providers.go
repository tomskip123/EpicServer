package auth

import (
	"strings"

	"golang.org/x/oauth2"
)

// wellKnownProviderEndpoints covers common OAuth providers for quick setup.
var wellKnownProviderEndpoints = map[string]oauth2.Endpoint{
	"github": {
		AuthURL:  "https://github.com/login/oauth/authorize",
		TokenURL: "https://github.com/login/oauth/access_token",
	},
	"gitlab": {
		AuthURL:  "https://gitlab.com/oauth/authorize",
		TokenURL: "https://gitlab.com/oauth/token",
	},
	"google": {
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
	},
	"microsoft": {
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
	},
}

var wellKnownProviderScopes = map[string][]string{
	"github":    {"read:user", "user:email"},
	"gitlab":    {"read_user"},
	"google":    {"openid", "profile", "email"},
	"microsoft": {"openid", "profile", "email"},
}

// EndpointForProvider returns the well-known OAuth2 endpoints for a known provider.
func EndpointForProvider(provider string) (oauth2.Endpoint, bool) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	ep, ok := wellKnownProviderEndpoints[provider]
	return ep, ok
}

// DefaultScopesForProvider returns a copy of the default scopes for the given provider.
func DefaultScopesForProvider(provider string) []string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if scopes, ok := wellKnownProviderScopes[provider]; ok {
		return append([]string(nil), scopes...)
	}
	return nil
}
