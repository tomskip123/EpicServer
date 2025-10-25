package epicserver

import (
	"container/list"
	"sync"
	"time"
)

type cacheEntry struct {
	key     string
	payload []byte
	expires time.Time
	elem    *list.Element
}

type queryCache struct {
	ttl        time.Duration
	maxEntries int

	mu    sync.Mutex
	items map[string]*cacheEntry
	order *list.List
}

func newQueryCache(defaultTTL time.Duration, maxEntries int) *queryCache {
	if defaultTTL <= 0 {
		defaultTTL = 30 * time.Second
	}

	return &queryCache{
		ttl:        defaultTTL,
		maxEntries: maxEntries,
		items:      make(map[string]*cacheEntry),
		order:      list.New(),
	}
}

func (c *queryCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expires) {
		c.removeEntry(entry)
		return nil, false
	}

	c.order.MoveToFront(entry.elem)
	return entry.payload, true
}

func (c *queryCache) set(key string, payload []byte, ttl time.Duration) {
	if len(payload) == 0 {
		return
	}

	if ttl <= 0 {
		ttl = c.ttl
	}

	entry := &cacheEntry{
		key:     key,
		payload: payload,
		expires: time.Now().Add(ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.items[key]; ok {
		existing.payload = payload
		existing.expires = entry.expires
		c.order.MoveToFront(existing.elem)
		return
	}

	entry.elem = c.order.PushFront(key)
	c.items[key] = entry
	c.trim()
}

func (c *queryCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		c.removeEntry(entry)
	}
}

func (c *queryCache) trim() {
	if c.maxEntries <= 0 {
		return
	}

	for len(c.items) > c.maxEntries {
		back := c.order.Back()
		if back == nil {
			break
		}
		if key, ok := back.Value.(string); ok {
			if entry, ok := c.items[key]; ok {
				c.removeEntry(entry)
				continue
			}
		}
		c.order.Remove(back)
	}
}

func (c *queryCache) removeEntry(entry *cacheEntry) {
	delete(c.items, entry.key)
	if entry.elem != nil {
		c.order.Remove(entry.elem)
	}
}
