package services

import (
	"context"
	"encoding/base64"
	"os"

	"github.com/coreos/go-oidc"
	"github.com/cyberthy/server/structs"
	"golang.org/x/oauth2"
)

func NewAuthConfig(ctx context.Context, clientId string, clientSecret string, cookieName string, redirect string) *structs.Auth {
	CheckAndSetKeys()

	ch := structs.NewCookieHandler()

	auth := structs.Auth{
		Provider:       nil,
		Config:         &oauth2.Config{},
		Verifier:       nil,
		CookieHandler:  ch,
		AuthCookieName: cookieName,
	}

	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		// handle error
	}

	// Configure an OpenID Connect aware OAuth2 client.
	auth.Config = &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  redirect,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	auth.Verifier = provider.Verifier(&oidc.Config{ClientID: clientId})

	return &auth
}

func CheckAndSetKeys() {
	// Get the base64-encoded keys from environment variables
	hashKeyBase64 := os.Getenv("SECURE_COOKIE_HASH_KEY")
	blockKeyBase64 := os.Getenv("SECURE_COOKIE_BLOCK_KEY")

	// Decode the base64-encoded keys
	hashKey, err := base64.StdEncoding.DecodeString(hashKeyBase64)
	if err != nil {
		panic("Failed to decode hash key: " + err.Error())
	}

	blockKey, err := base64.StdEncoding.DecodeString(blockKeyBase64)
	if err != nil {
		panic("Failed to decode block key: " + err.Error())
	}

	// Ensure the keys are of valid length for AES
	if len(hashKey) != 32 || len(blockKey) != 32 {
		panic("Keys must be 32 bytes long")
	}
}
