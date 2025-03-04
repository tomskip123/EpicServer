// Package EpicServerCache provides caching solutions for the EpicServer framework.
// It includes implementations for in-memory caching, Redis, and other cache providers,
// allowing you to easily integrate different caching strategies with your application.
//
// This package handles cache initialization, item storage and retrieval, expiration,
// and automatic cleanup of expired items.
//
// # Memory Cache Example
//
//	import (
//	    "time"
//	    "github.com/tomskip123/EpicServer/v2"
//	    "github.com/tomskip123/EpicServer/v2/cache"
//	)
//
//	// Configure memory cache
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServerCache.WithMemoryCache(&EpicServerCache.MemoryCacheConfig{
//	        Name:            "default",
//	        DefaultTTL:      5 * time.Minute,
//	        CleanupInterval: 1 * time.Minute,
//	        MaxItems:        1000,
//	    }),
//	})
//
//	// Use cache in a handler
//	func GetUserProfile(c *gin.Context) {
//	    userID := c.Param("id")
//	    cacheKey := "user:" + userID
//
//	    // Try to get from cache first
//	    cache := EpicServerCache.GetMemoryCache(server, "default")
//	    if userData, found := cache.Get(cacheKey); found {
//	        c.JSON(200, userData)
//	        return
//	    }
//
//	    // Not in cache, fetch from database
//	    user, err := fetchUserFromDatabase(userID)
//	    if err != nil {
//	        c.JSON(500, gin.H{"error": "Database error"})
//	        return
//	    }
//
//	    // Store in cache for future requests
//	    cache.Set(cacheKey, user, 10*time.Minute)
//	    c.JSON(200, user)
//	}
package EpicServerCache

import (
	"math"
	"sync"
	"time"

	"github.com/tomskip123/EpicServer/v2"
)

// MemoryCacheConfig contains configuration for memory cache.
// This struct defines the behavior and limits of the in-memory cache.
//
// Example:
//
//	config := &EpicServerCache.MemoryCacheConfig{
//	    Name:            "sessions",
//	    DefaultTTL:      30 * time.Minute,
//	    CleanupInterval: 5 * time.Minute,
//	    MaxItems:        10000,
//	}
type MemoryCacheConfig struct {
	// Name is the unique identifier for this cache
	Name string
	// Type is the cache type (always "memory" for this implementation)
	Type string
	// DefaultTTL is the default time-to-live for cache items
	DefaultTTL time.Duration
	// CleanupInterval is how often to check for expired items
	CleanupInterval time.Duration
	// MaxItems is the maximum number of items to store (0 = unlimited)
	MaxItems int
	// Cache is the actual cache instance
	Cache *MemoryCache
}

// item represents a cached item with expiration time
type item struct {
	value      interface{}
	expiration int64
	size       int
}

// MemoryCache implements an in-memory cache with TTL support.
// It provides thread-safe operations for storing and retrieving cached items,
// with automatic expiration and cleanup of expired items.
//
// The cache uses a map internally with a read-write mutex for thread safety.
type MemoryCache struct {
	items            map[string]item
	mu               sync.RWMutex
	defaultTTL       time.Duration
	janitorRunning   bool
	cleanupInterval  time.Duration
	maxItems         int
	currentItemCount int
}

// NewMemoryCache creates a new memory cache with the given configuration.
// It initializes the cache and starts the janitor process if a cleanup interval is specified.
//
// Parameters:
//   - defaultTTL: Default time-to-live for items (0 means no expiration)
//   - cleanupInterval: How often to check for and remove expired items (0 disables cleanup)
//   - maxItems: Maximum number of items to store (0 means unlimited)
//
// Example:
//
//	cache := EpicServerCache.NewMemoryCache(5*time.Minute, time.Minute, 1000)
func NewMemoryCache(defaultTTL, cleanupInterval time.Duration, maxItems int) *MemoryCache {
	cache := &MemoryCache{
		items:           make(map[string]item),
		defaultTTL:      defaultTTL,
		cleanupInterval: cleanupInterval,
		maxItems:        maxItems,
	}

	// Start the cleanup routine if interval is greater than 0
	if cleanupInterval > 0 {
		cache.startJanitor()
	}

	return cache
}

// startJanitor starts a goroutine that periodically cleanups expired items.
// This method is called internally by NewMemoryCache when a cleanup interval is specified.
func (c *MemoryCache) startJanitor() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.janitorRunning {
		return
	}

	c.janitorRunning = true
	go c.janitor()
}

// janitor runs cleanup at regular intervals.
// This is an internal method used by the cleanup goroutine.
func (c *MemoryCache) janitor() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.DeleteExpired()
	}
}

// Set adds an item to the cache with the specified expiration.
// If duration is 0, the default TTL is used. If the default TTL is also 0,
// the item will never expire.
//
// If the cache has reached its maximum capacity (MaxItems), the oldest item
// will be evicted to make room for the new item.
//
// Example:
//
//	// Cache an item for 10 minutes
//	cache.Set("user:123", userData, 10*time.Minute)
//
//	// Cache an item with the default TTL
//	cache.Set("settings", appSettings, 0)
func (c *MemoryCache) Set(key string, value interface{}, duration time.Duration) {
	var expiration int64

	// Calculate expiration time
	if duration == 0 {
		duration = c.defaultTTL
	}

	if duration > 0 {
		expiration = time.Now().Add(duration).UnixNano()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict an item due to max items limit
	if c.maxItems > 0 && len(c.items) >= c.maxItems && c.items[key].value == nil {
		// Evict the oldest item (simple strategy)
		var oldestKey string
		var oldestTime int64 = math.MaxInt64

		for k, v := range c.items {
			if v.expiration > 0 && v.expiration < oldestTime {
				oldestKey = k
				oldestTime = v.expiration
			}
		}

		if oldestKey != "" {
			delete(c.items, oldestKey)
		}
	}

	// Store the item
	c.items[key] = item{
		value:      value,
		expiration: expiration,
	}
}

// Get retrieves an item from the cache.
// It returns the cached value and a boolean indicating whether the item was found.
// If the item has expired, it will be deleted and the method will return false.
//
// Example:
//
//	if userData, found := cache.Get("user:123"); found {
//	    // Use cached data
//	    return userData.(*User), nil
//	}
//	// Item not in cache or expired, fetch from source
func (c *MemoryCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	item, exists := c.items[key]
	if !exists {
		c.mu.RUnlock()
		return nil, false
	}

	// Check if the item has expired
	if item.expiration > 0 && time.Now().UnixNano() > item.expiration {
		c.mu.RUnlock()
		// Item has expired, delete it in a separate goroutine to avoid blocking
		go c.Delete(key)
		return nil, false
	}

	c.mu.RUnlock()
	return item.value, true
}

// Delete removes an item from the cache.
// If the item doesn't exist, this operation is a no-op.
//
// Example:
//
//	// Remove a user from cache when they log out
//	cache.Delete("user:" + userID)
func (c *MemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// DeleteExpired removes all expired items from the cache.
// This method is called automatically by the janitor at the specified cleanup interval,
// but can also be called manually if needed.
//
// Example:
//
//	// Force cleanup of expired items
//	cache.DeleteExpired()
func (c *MemoryCache) DeleteExpired() {
	now := time.Now().UnixNano()

	c.mu.Lock()
	defer c.mu.Unlock()

	for k, v := range c.items {
		if v.expiration > 0 && now > v.expiration {
			delete(c.items, k)
		}
	}
}

// Flush removes all items from the cache.
// This is useful when you need to clear the entire cache, for example
// when deploying a new version of your application.
//
// Example:
//
//	// Clear all cached items
//	cache.Flush()
func (c *MemoryCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]item)
}

// ItemCount returns the number of items in the cache.
// This can be useful for monitoring cache usage.
//
// Example:
//
//	count := cache.ItemCount()
//	log.Printf("Cache contains %d items", count)
func (c *MemoryCache) ItemCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// GetMemoryCache retrieves a memory cache instance from the server.
// This function is used to access a previously configured cache by its name.
//
// Example:
//
//	// Get the default cache
//	cache := EpicServerCache.GetMemoryCache(server, "default")
//
//	// Use the cache
//	if value, found := cache.Get("key"); found {
//	    // Use cached value
//	}
func GetMemoryCache(s *EpicServer.Server, name string) *MemoryCache {
	if cache, ok := s.Cache[name].(*MemoryCacheConfig); ok {
		return cache.Cache
	}
	panic("not a memory cache")
}

// WithMemoryCache adds a memory cache to the server.
// This function creates an AppLayer that initializes a memory cache
// with the specified configuration when the server starts.
//
// Example:
//
//	server.UpdateAppLayer([]EpicServer.AppLayer{
//	    EpicServerCache.WithMemoryCache(&EpicServerCache.MemoryCacheConfig{
//	        Name:            "default",
//	        DefaultTTL:      5 * time.Minute,
//	        CleanupInterval: 1 * time.Minute,
//	        MaxItems:        1000,
//	    }),
//	})
func WithMemoryCache(config *MemoryCacheConfig) EpicServer.AppLayer {
	// Set default values if not specified
	if config.DefaultTTL <= 0 {
		config.DefaultTTL = 5 * time.Minute
	}

	if config.CleanupInterval <= 0 {
		config.CleanupInterval = time.Minute
	}

	return func(s *EpicServer.Server) {
		config.Cache = NewMemoryCache(config.DefaultTTL, config.CleanupInterval, config.MaxItems)
		s.Cache[config.Name] = config

		s.Logger.Info("Memory cache initialized",
			EpicServer.F("name", config.Name),
			EpicServer.F("default_ttl", config.DefaultTTL.String()),
			EpicServer.F("cleanup_interval", config.CleanupInterval.String()))
	}
}
