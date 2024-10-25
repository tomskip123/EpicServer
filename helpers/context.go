package helpers

import (
	"errors"
	"fmt"
	"time"

	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

var (
	ErrNoAuthUserContext = errors.New("no_auth_user")
)

var (
	UserMemoryCache = make(map[string]*structs.UserMemoryCacheItem)
)

func GetAuthenticatedUser(ctx *gin.Context, app *structs.App) (*structs.UserMemoryCacheItem, error) {
	authUser, exists := ctx.Get("auth_user")
	if !exists {
		return nil, ErrNoAuthUserContext
	}

	return determineCache(authUser.(*structs.CookieContents), app)
}

func UpdateMemoryCache(ctx *gin.Context, app *structs.App, updated structs.UserMemoryCacheItem) (*structs.UserMemoryCacheItem, error) {
	authUser, exists := ctx.MustGet("auth_user").(*structs.CookieContents)
	if !exists {
		return nil, ErrNoAuthUserContext
	}

	item, err := determineCache(authUser, app)
	if err != nil {
		return nil, err
	}

	// this should update it.
	item.Settings = updated.Settings

	return nil, nil
}

func determineCache(authUser *structs.CookieContents, app *structs.App) (*structs.UserMemoryCacheItem, error) {
	userCacheItem := getCacheItem(authUser)
	if userCacheItem == nil {
		// get user from db and update the cache item using memory address
		err := getUserFromDB(authUser, app)
		if err != nil {
			return nil, err
		}

		return UserMemoryCache[authUser.UserId], nil
	}

	return userCacheItem, nil
}

func getCacheItem(authUser *structs.CookieContents) *structs.UserMemoryCacheItem {
	cacheItem := UserMemoryCache[authUser.UserId]
	if cacheItem != nil {
		if time.Now().Before(cacheItem.Expiry) {
			fmt.Println("Using cache")
			return cacheItem
		} else {
			// Remove expired cache item
			delete(UserMemoryCache, authUser.UserId)
			return nil
		}
	}

	return cacheItem
}

func getUserFromDB(authUser *structs.CookieContents, app *structs.App) error {
	user, err := app.Database.SystemCollections.User.FindOne(authUser.UserId)
	if err != nil {
		return err
	}

	UserMemoryCache[authUser.UserId] = &structs.UserMemoryCacheItem{
		UserId:   authUser.UserId,
		Features: user.Features,
		Expiry:   time.Now().Add(24 * time.Hour),
		Image:    user.AvatarImage,
	}

	if user.Settings != nil {
		UserMemoryCache[authUser.UserId].Settings = *user.Settings
	}

	return nil
}
