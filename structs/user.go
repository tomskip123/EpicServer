package structs

import (
	"time"

	"github.com/cyberthy/server/db"
)

type UserMemoryCacheItem struct {
	UserId   string
	Features []string
	Expiry   time.Time
	Settings db.SettingsModel
	Image    string
}

func (um *UserMemoryCacheItem) HasFeature(feature string) bool {
	for _, f := range um.Features {
		if f == feature {
			return true
		}
	}

	return false
}

func (um *UserMemoryCacheItem) Remove(userId string, userMemoryCache map[string]*UserMemoryCacheItem) bool {
	if userMemoryCache[userId] != nil {
		delete(userMemoryCache, userId)
		return true
	}

	return false
}
