package EpicServerCache

import (
	"sync"
	"time"

	"github.com/tomskip123/EpicServer"
)

type MemoryCacheConfig struct {
	Name  string
	Type  string
	Cache *MemoryCache
}

type item struct {
	value      interface{}
	expiration int64
}

type MemoryCache struct {
	items map[string]item
	mu    sync.RWMutex
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		items: make(map[string]item),
	}
}

func (c *MemoryCache) Set(key string, value interface{}, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiration := time.Now().Add(duration).UnixNano()
	c.items[key] = item{
		value:      value,
		expiration: expiration,
	}
}

func (c *MemoryCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.items[key]
	if !exists {
		return nil, false
	}

	if time.Now().UnixNano() > item.expiration {
		return nil, false
	}

	return item.value, true
}

func (c *MemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

func GetMemoryCache(s *EpicServer.Server, name string) *MemoryCache {
	if cache, ok := s.Cache[name].(*MemoryCacheConfig); ok {
		return cache.Cache
	}
	panic("not a memory cache")
}

func WithMemoryCache(config *MemoryCacheConfig) EpicServer.AppLayer {
	return func(s *EpicServer.Server) {
		s.Cache[config.Name] = config
		s.Cache[config.Name].(*MemoryCacheConfig).Cache = NewMemoryCache()
	}
}
