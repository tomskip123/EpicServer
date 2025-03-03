package EpicServerCache

import (
	"math"
	"sync"
	"time"

	"github.com/tomskip123/EpicServer/v2"
)

// MemoryCacheConfig contains configuration for memory cache
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

// MemoryCache implements an in-memory cache with TTL support
type MemoryCache struct {
	items            map[string]item
	mu               sync.RWMutex
	defaultTTL       time.Duration
	janitorRunning   bool
	cleanupInterval  time.Duration
	maxItems         int
	currentItemCount int
}

// NewMemoryCache creates a new memory cache with the given configuration
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

// startJanitor starts a goroutine that periodically cleanups expired items
func (c *MemoryCache) startJanitor() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.janitorRunning {
		return
	}

	c.janitorRunning = true
	go c.janitor()
}

// janitor runs cleanup at regular intervals
func (c *MemoryCache) janitor() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.DeleteExpired()
	}
}

// Set adds an item to the cache with the specified expiration
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

// Get retrieves an item from the cache
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

// Delete removes an item from the cache
func (c *MemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// DeleteExpired removes all expired items from the cache
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

// Flush removes all items from the cache
func (c *MemoryCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]item)
}

// ItemCount returns the number of items in the cache
func (c *MemoryCache) ItemCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// GetMemoryCache retrieves a memory cache instance from the server
func GetMemoryCache(s *EpicServer.Server, name string) *MemoryCache {
	if cache, ok := s.Cache[name].(*MemoryCacheConfig); ok {
		return cache.Cache
	}
	panic("not a memory cache")
}

// WithMemoryCache adds a memory cache to the server
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
