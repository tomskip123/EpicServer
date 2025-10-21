package auth

import (
	"context"
	"log"
	"net/http"
)

// AuthOption configures AuthModule.
type AuthOption func(*AuthModule)

// Middleware composes an http.Handler.
type Middleware func(http.Handler) http.Handler

// Loggers groups the Info and Error loggers used by the auth module.
type Loggers struct {
	Error *log.Logger
	Info  *log.Logger
}

// UserRegistrar captures the subset of user management behavior required by the auth module.
type UserRegistrar interface {
	IsEnabled() bool
	RegisterUser(ctx context.Context, user *StatelessUser) (any, error)
}

// Dependencies captures the cross-package wiring needed by the auth module.
type Dependencies struct {
	Loggers         Loggers
	User            UserRegistrar
	DefaultProvider string
}

// StatelessUser represents a user returned by the OAuth provider.
type StatelessUser struct {
	Name    string
	Email   string
	Picture string
}
