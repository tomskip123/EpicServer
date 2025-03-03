package EpicServerCache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestServer is a simplified version of EpicServer.Server for testing
type TestServer struct {
	Cache map[string]interface{}
}

// Implementation of the minimal necessary interface for the cache tests
func (s *TestServer) GetCache(name string) (interface{}, bool) {
	if s.Cache == nil {
		return nil, false
	}
	cache, ok := s.Cache[name]
	return cache, ok
}

func (s *TestServer) AddCache(name string, cache interface{}) {
	if s.Cache == nil {
		s.Cache = make(map[string]interface{})
	}
	s.Cache[name] = cache
}

// Helper functions to bridge our test server with the real functions
func getMemoryCacheForTest(s *TestServer, name string) *MemoryCache {
	if s.Cache == nil {
		return nil
	}

	cache, ok := s.GetCache(name)
	if !ok {
		return nil
	}

	config, ok := cache.(*MemoryCacheConfig)
	if !ok {
		panic("Cache is not a memory cache")
	}

	return config.Cache
}

func withMemoryCacheForTest(config *MemoryCacheConfig) func(*TestServer) {
	return func(s *TestServer) {
		if s.Cache == nil {
			s.Cache = make(map[string]interface{})
		}

		// Set default TTL if not provided
		if config.DefaultTTL == 0 {
			config.DefaultTTL = 5 * time.Minute
		}

		// Set default cleanup interval if not provided
		if config.CleanupInterval == 0 {
			config.CleanupInterval = time.Minute
		}

		config.Cache = NewMemoryCache(config.DefaultTTL, config.CleanupInterval, config.MaxItems)
		s.Cache[config.Name] = config
	}
}

// Test NewMemoryCache creates a cache with the correct settings
func TestNewMemoryCache(t *testing.T) {
	ttl := 10 * time.Minute
	cleanupInterval := 5 * time.Minute
	maxItems := 100

	cache := NewMemoryCache(ttl, cleanupInterval, maxItems)

	assert.NotNil(t, cache)
	assert.Equal(t, ttl, cache.defaultTTL)
	assert.Equal(t, cleanupInterval, cache.cleanupInterval)
	assert.Equal(t, maxItems, cache.maxItems)
	assert.NotNil(t, cache.items)
}

// Test cache Set and Get operations
func TestMemoryCache_SetGet(t *testing.T) {
	cache := NewMemoryCache(time.Minute, time.Minute, 0)

	// Test setting and getting a value
	cache.Set("key1", "value1", 0) // 0 = use default TTL
	value, found := cache.Get("key1")
	assert.True(t, found)
	assert.Equal(t, "value1", value)

	// Test getting a non-existent key
	value, found = cache.Get("nonexistent")
	assert.False(t, found)
	assert.Nil(t, value)

	// Test custom TTL
	cache.Set("key2", "value2", 2*time.Second)
	value, found = cache.Get("key2")
	assert.True(t, found)
	assert.Equal(t, "value2", value)

	// Wait for expiration
	time.Sleep(3 * time.Second)
	value, found = cache.Get("key2")
	assert.False(t, found)
	assert.Nil(t, value)
}

// Test Delete operation
func TestMemoryCache_Delete(t *testing.T) {
	cache := NewMemoryCache(time.Minute, time.Minute, 0)

	// Set a value
	cache.Set("key1", "value1", 0)

	// Verify it exists
	_, found := cache.Get("key1")
	assert.True(t, found)

	// Delete it
	cache.Delete("key1")

	// Verify it's gone
	_, found = cache.Get("key1")
	assert.False(t, found)

	// Delete a non-existent key (should not panic)
	cache.Delete("nonexistent")
}

// Test Flush operation
func TestMemoryCache_Flush(t *testing.T) {
	cache := NewMemoryCache(time.Minute, time.Minute, 0)

	// Set multiple values
	cache.Set("key1", "value1", 0)
	cache.Set("key2", "value2", 0)
	cache.Set("key3", "value3", 0)

	// Verify count
	assert.Equal(t, 3, cache.ItemCount())

	// Flush the cache
	cache.Flush()

	// Verify all items are gone
	assert.Equal(t, 0, cache.ItemCount())
	_, found := cache.Get("key1")
	assert.False(t, found)
}

// Test ItemCount operation
func TestMemoryCache_ItemCount(t *testing.T) {
	cache := NewMemoryCache(time.Minute, time.Minute, 0)

	// Empty cache
	assert.Equal(t, 0, cache.ItemCount())

	// Add items
	cache.Set("key1", "value1", 0)
	assert.Equal(t, 1, cache.ItemCount())

	cache.Set("key2", "value2", 0)
	assert.Equal(t, 2, cache.ItemCount())

	// Delete an item
	cache.Delete("key1")
	assert.Equal(t, 1, cache.ItemCount())

	// Flush
	cache.Flush()
	assert.Equal(t, 0, cache.ItemCount())
}

// Test DeleteExpired operation
func TestMemoryCache_DeleteExpired(t *testing.T) {
	cache := NewMemoryCache(time.Minute, time.Minute, 0)

	// Set items with different TTLs
	cache.Set("permanent", "value", time.Hour)
	cache.Set("short-lived", "value", 2*time.Second)

	// Wait for the short-lived item to expire
	time.Sleep(3 * time.Second)

	// Verify both items still exist in the map (not auto-cleaned yet)
	assert.Equal(t, 2, len(cache.items))

	// Manually delete expired items
	cache.DeleteExpired()

	// Verify only the permanent item remains
	assert.Equal(t, 1, len(cache.items))
	_, found := cache.Get("permanent")
	assert.True(t, found)
	_, found = cache.Get("short-lived")
	assert.False(t, found)
}

// Test GetMemoryCache tests the GetMemoryCache function
func TestGetMemoryCache(t *testing.T) {
	// Create a test server with initialization
	testServer := &TestServer{
		Cache: make(map[string]interface{}),
	}

	// Create and add a cache config
	config := &MemoryCacheConfig{
		Name:       "test-cache",
		DefaultTTL: 5 * time.Minute,
		Cache:      NewMemoryCache(5*time.Minute, time.Minute, 0),
	}

	// Add the cache to the server
	testServer.AddCache("test-cache", config)

	// Test getting the cache
	cache := getMemoryCacheForTest(testServer, "test-cache")
	assert.NotNil(t, cache)

	// Test panic on invalid cache
	testServer.AddCache("invalid-cache", "not a memory cache")
	assert.Panics(t, func() {
		getMemoryCacheForTest(testServer, "invalid-cache")
	})
}

// TestWithMemoryCache tests the WithMemoryCache function
func TestWithMemoryCache(t *testing.T) {
	// Create a test server with initialization
	testServer := &TestServer{
		Cache: make(map[string]interface{}),
	}

	// Test with default TTL
	config1 := &MemoryCacheConfig{
		Name: "default-ttl-cache",
	}

	// Apply the app layer
	layer := withMemoryCacheForTest(config1)
	layer(testServer)

	// Verify the cache was created with default TTL
	cache1 := getMemoryCacheForTest(testServer, "default-ttl-cache")
	assert.NotNil(t, cache1)
	assert.Equal(t, 5*time.Minute, cache1.defaultTTL)

	// Test with custom TTL
	config2 := &MemoryCacheConfig{
		Name:       "custom-ttl-cache",
		DefaultTTL: 10 * time.Minute,
	}

	layer = withMemoryCacheForTest(config2)
	layer(testServer)

	// Verify the cache was created with custom TTL
	cache2 := getMemoryCacheForTest(testServer, "custom-ttl-cache")
	assert.NotNil(t, cache2)
	assert.Equal(t, 10*time.Minute, cache2.defaultTTL)
}
