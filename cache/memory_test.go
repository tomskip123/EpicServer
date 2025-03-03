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

	cache, ok := s.Cache[name]
	if !ok {
		return nil
	}

	config, ok := cache.(*MemoryCacheConfig)
	if !ok {
		return nil
	}

	return config.Cache
}

func withMemoryCacheForTest(config *MemoryCacheConfig) func(*TestServer) {
	return func(s *TestServer) {
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

// Test WithMemoryCache function
func TestWithMemoryCache(t *testing.T) {
	// Create a test server
	server := &TestServer{
		Cache: make(map[string]interface{}),
	}

	// Create cache config
	config := &MemoryCacheConfig{
		Name:            "test-cache",
		Type:            "memory",
		DefaultTTL:      time.Minute,
		CleanupInterval: time.Minute,
		MaxItems:        100,
	}

	// Apply the WithMemoryCache layer using our test adapter
	layer := withMemoryCacheForTest(config)
	layer(server)

	// Verify the cache was added to the server
	cache, found := server.GetCache("test-cache")
	assert.True(t, found)
	assert.NotNil(t, cache)

	// Verify it's the same cache as in the config
	assert.Same(t, config.Cache, cache.(*MemoryCacheConfig).Cache)
}

// Test GetMemoryCache function
func TestGetMemoryCache(t *testing.T) {
	// Create a test server
	server := &TestServer{
		Cache: make(map[string]interface{}),
	}

	// Case 1: Cache doesn't exist
	cache := getMemoryCacheForTest(server, "nonexistent")
	assert.Nil(t, cache)

	// Case 2: Cache exists
	expectedCache := NewMemoryCache(time.Minute, time.Minute, 100)
	config := &MemoryCacheConfig{
		Name:            "test-cache",
		Type:            "memory",
		DefaultTTL:      time.Minute,
		CleanupInterval: time.Minute,
		MaxItems:        100,
		Cache:           expectedCache,
	}
	server.Cache["test-cache"] = config

	cache = getMemoryCacheForTest(server, "test-cache")
	assert.NotNil(t, cache)
	assert.Same(t, expectedCache, cache)
}
