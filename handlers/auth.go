package handlers

import (
	"errors"
	"net/http"

	"github.com/cyberthy/server/helpers"
	"github.com/cyberthy/server/middleware"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

func RegisterAuthRoutes(r *gin.Engine, app *structs.App) {
	// r.Use(middleware.RateLimitMiddleware())

	r.GET("/auth/google", HandleAuthGoogle(app))
	r.GET("/auth/google/callback", HandleAuthGoogleCallback(app))
	r.GET("/auth/logout", HandleAuthLogout(app))
}

func HandleAuthGoogle(app *structs.App) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Redirect(http.StatusSeeOther, app.Auth.Config.AuthCodeURL("state"))
	}
}

func HandleAuthGoogleCallback(app *structs.App) gin.HandlerFunc {
	userCol := app.Database.SystemCollections.User

	return func(ctx *gin.Context) {
		// Verify state and errors.
		oauth2Token, err := app.Auth.Config.Exchange(ctx, ctx.Query("code"))
		if err != nil {
			// handle
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			// handle missing token
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := app.Auth.Verifier.Verify(ctx, rawIDToken)
		if err != nil {
			// handle error
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// Extract custom claims
		var claims structs.Claims

		if err := idToken.Claims(&claims); err != nil {
			// handle error
			ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		// now we save or check user
		user, err := userCol.FindOneByEmail(claims.Email)
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				user, err = userCol.Create(claims.Email, claims.Name, claims.Picture)
				if err != nil {
					ctx.AbortWithError(http.StatusInternalServerError, err)
					return
				}
			}
		}

		err = app.Auth.CookieHandler.SetCookieHandler(
			ctx,
			&structs.CookieContents{
				Email:  user.Email,
				UserId: user.ID,
			},
			"sesh_name",
			app.Config,
		)

		if err != nil {
			return
		}

		ctx.Redirect(http.StatusSeeOther, "/")
	}
}

func HandleAuthLogout(app *structs.App) gin.HandlerFunc {
	return middleware.WithAuth(app, []string{}, func(ctx *gin.Context, authUser *structs.UserMemoryCacheItem) {
		authUser.Remove(authUser.UserId, helpers.UserMemoryCache)
		// TODO: replace with configs
		ctx.SetCookie(
			"sesh_name", // Cookie name
			"",          // Cookie value
			-1,          // Max age (negative value to expire the cookie)
			"/",         // Path
			app.Config.CookieDomain,
			app.Config.CookieSecure, // Secure
			true,                    // HTTPOnly
		)

		ctx.Redirect(http.StatusSeeOther, "/")
	})
}
