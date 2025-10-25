package epicserver

import "sync"

type EpicMemoryCache struct {
	mu    sync.Mutex
	cache map[string]any
}

// NewEpicMemoryCache returns a new memory cache for you to assign to a variable that
// can be stored in memory - duh
func NewEpicMemoryCache() *EpicMemoryCache {
	return &EpicMemoryCache{
		mu:    sync.Mutex{},
		cache: make(map[string]any),
	}
}

func (emc *EpicMemoryCache) Get(key string) any {
	return emc.cache[key]
}

func (emc *EpicMemoryCache) Set(key string, value any) {
	emc.mu.Lock()
	defer emc.mu.Unlock()
	emc.cache[key] = value
}

func (emc *EpicMemoryCache) Remove(key string) bool {
	emc.mu.Lock()
	defer emc.mu.Unlock()

	delete(emc.cache, key)
	return true
}
