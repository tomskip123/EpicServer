package auth

import (
	"sync"
	"time"
)

type StateStoreItem struct {
	Expiry   time.Time
	Redirect string
}

// TODO: do we provide more options than just an in-memory store for temporarily storing
// state between auth2 redirects?
type stateStore struct {
	mu    sync.Mutex
	items map[string]StateStoreItem
}

func newStateStore() *stateStore {
	return &stateStore{items: make(map[string]StateStoreItem)}
}

// set a value based off a random string.
func (s *stateStore) New(ttl time.Duration, now func() time.Time, redirect string) (string, error) {
	value, err := randomString(32)
	if err != nil {
		return "", err
	}

	expires := now().Add(ttl)
	s.mu.Lock()

	s.items[value] = StateStoreItem{
		Expiry:   expires,
		Redirect: redirect,
	}

	s.mu.Unlock()
	return value, nil
}

// Once a value has been read, it is destroyed.
func (s *stateStore) Consume(value string, now time.Time) *StateStoreItem {
	s.mu.Lock()

	stateItem, ok := s.items[value]
	if ok {
		delete(s.items, value)
	}

	s.mu.Unlock()
	if !ok {
		return nil
	}

	return &stateItem
}
