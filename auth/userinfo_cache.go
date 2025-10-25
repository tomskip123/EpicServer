package auth

import "sync"

type UserInfoCache struct {
	mu    *sync.Mutex
	cache map[string]*StatelessUser
}

// STORED IN MEMORY
var userInfoCache = UserInfoCache{
	mu:    &sync.Mutex{},
	cache: make(map[string]*StatelessUser),
}

func (uic *UserInfoCache) Add(user *StatelessUser) {
	uic.mu.Lock()
	defer uic.mu.Unlock()

	uic.cache[user.Email] = user
}

func (uic *UserInfoCache) Get(email string) *StatelessUser {
	return uic.cache[email]
}
