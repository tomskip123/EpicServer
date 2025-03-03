package EpicServerCache

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tomskip123/EpicServer/v2"
)

// TestServer is a simplified version of EpicServer.Server for testing
type TestServer struct {
	Cache  map[string]interface{}
	Logger EpicServer.Logger
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

// Mock logger for testing
type testLogger struct{}

func (l *testLogger) Debug(msg string, fields ...EpicServer.LogField)            {}
func (l *testLogger) Info(msg string, fields ...EpicServer.LogField)             {}
func (l *testLogger) Warn(msg string, fields ...EpicServer.LogField)             {}
func (l *testLogger) Error(msg string, fields ...EpicServer.LogField)            {}
func (l *testLogger) Fatal(msg string, fields ...EpicServer.LogField)            {}
func (l *testLogger) WithFields(fields ...EpicServer.LogField) EpicServer.Logger { return l }
func (l *testLogger) WithModule(module string) EpicServer.Logger                 { return l }
func (l *testLogger) SetOutput(io.Writer)                                        {}
func (l *testLogger) SetLevel(EpicServer.LogLevel)                               {}
func (l *testLogger) SetFormat(EpicServer.LogFormat)                             {}
func (l *testLogger) SetRegistry(registry *EpicServer.LogRegistry)               {}

// TestWithMemoryCache tests the WithMemoryCache function
func TestWithMemoryCache(t *testing.T) {
	// Test with default values
	config := &MemoryCacheConfig{
		Name: "testCache",
		Type: "memory",
	}

	// Create the app layer
	appLayer := WithMemoryCache(config)

	// Create a server to apply the layer to
	s := &EpicServer.Server{
		Cache:  make(map[string]interface{}),
		Logger: &testLogger{},
	}

	// Apply the layer
	appLayer(s)

	// Verify that the cache was added to the server
	cachedConfig, ok := s.Cache["testCache"].(*MemoryCacheConfig)
	assert.True(t, ok, "Should add a MemoryCacheConfig to the server")
	assert.NotNil(t, cachedConfig.Cache, "Should initialize the cache")

	// Verify default values were set
	assert.Equal(t, 5*time.Minute, cachedConfig.DefaultTTL, "Should set default TTL")
	assert.Equal(t, time.Minute, cachedConfig.CleanupInterval, "Should set default cleanup interval")

	// Test with custom values
	customConfig := &MemoryCacheConfig{
		Name:            "customCache",
		Type:            "memory",
		DefaultTTL:      10 * time.Minute,
		CleanupInterval: 2 * time.Minute,
		MaxItems:        100,
	}

	customAppLayer := WithMemoryCache(customConfig)
	customAppLayer(s)

	// Verify that the cache was added with custom settings
	customCachedConfig, ok := s.Cache["customCache"].(*MemoryCacheConfig)
	assert.True(t, ok, "Should add a custom MemoryCacheConfig to the server")
	assert.Equal(t, 10*time.Minute, customCachedConfig.DefaultTTL, "Should respect custom TTL")
	assert.Equal(t, 2*time.Minute, customCachedConfig.CleanupInterval, "Should respect custom cleanup interval")
	assert.Equal(t, 100, customCachedConfig.MaxItems, "Should respect custom max items")
}

// TestGetMemoryCache tests the GetMemoryCache function
func TestGetMemoryCache(t *testing.T) {
	// Create a server with a memory cache
	s := &EpicServer.Server{
		Cache: make(map[string]interface{}),
	}

	// Create and add a memory cache
	cacheConfig := &MemoryCacheConfig{
		Name:            "testCache",
		Type:            "memory",
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: time.Minute,
	}

	// Initialize the cache
	cacheConfig.Cache = NewMemoryCache(cacheConfig.DefaultTTL, cacheConfig.CleanupInterval, cacheConfig.MaxItems)

	// Add it to the server
	s.Cache["testCache"] = cacheConfig

	// Test retrieving the cache
	cache := GetMemoryCache(s, "testCache")
	assert.NotNil(t, cache, "Should retrieve the memory cache")
	assert.Equal(t, cacheConfig.Cache, cache, "Should retrieve the correct cache instance")

	// Test panic for non-existent cache
	assert.Panics(t, func() {
		GetMemoryCache(s, "nonExistentCache")
	}, "Should panic for non-existent cache")

	// Test panic for wrong cache type
	s.Cache["wrongType"] = "not a memory cache"
	assert.Panics(t, func() {
		GetMemoryCache(s, "wrongType")
	}, "Should panic for wrong cache type")
}
