package structs

import (
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type Auth struct {
	Provider       *oidc.Provider
	Config         *oauth2.Config
	Verifier       *oidc.IDTokenVerifier
	CookieHandler  *CookieHandler
	AuthCookieName string
}

type Claims struct {
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Verified    bool     `json:"email_verified"`
	UserID      string   `json:"user_id"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	Picture     string   `json:"picture"`
}
