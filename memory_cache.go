package epicserver

import (
	"sync"
)

type EpicMemoryCache[T any] struct {
	mu    sync.RWMutex
	cache map[string]T
}

// NewEpicMemoryCache returns a new memory cache for you to assign to a variable that
// can be stored in memory - duh
func NewEpicMemoryCache[T any]() *EpicMemoryCache[T] {
	return &EpicMemoryCache[T]{
		mu:    sync.RWMutex{},
		cache: make(map[string]T),
	}
}

// we use RLock and RUnlock in readers for concurrency
func (emc *EpicMemoryCache[T]) Get(key string) T {
	emc.mu.RLock()
	defer emc.mu.RUnlock()
	return emc.cache[key]
}

func (emc *EpicMemoryCache[T]) Set(key string, value T) {
	emc.mu.Lock()
	defer emc.mu.Unlock()
	emc.cache[key] = value
}

func (emc *EpicMemoryCache[T]) Remove(key string) bool {
	emc.mu.Lock()
	defer emc.mu.Unlock()

	delete(emc.cache, key)
	return true
}
