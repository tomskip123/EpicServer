package auth

import (
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// STORED IN MEMORY
// Session contains the OAuth token and expiry metadata.
type Session struct {
	ID        string
	Token     *oauth2.Token
	CreatedAt time.Time
	ExpiresAt time.Time
	Email     string
}

// Valid reports whether the session is still active.
func (s *Session) Valid(now time.Time) bool {
	return now.Before(s.ExpiresAt)
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*Session)}
}

func (s *sessionStore) Create(token *oauth2.Token, ttl time.Duration, now time.Time, email string) (*Session, error) {
	id, err := randomString(32)
	if err != nil {
		return nil, err
	}
	expiry := now.Add(ttl)
	if token != nil && !token.Expiry.IsZero() && token.Expiry.Before(expiry) {
		expiry = token.Expiry
	}
	session := &Session{
		ID:        id,
		Token:     token,
		CreatedAt: now,
		ExpiresAt: expiry,
		Email:     email,
	}
	s.mu.Lock()
	s.sessions[id] = session
	s.mu.Unlock()
	return session, nil
}

func (s *sessionStore) Get(id string, now time.Time) (*Session, bool) {
	s.mu.RLock()
	session, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !session.Valid(now) {
		s.Delete(id)
		return nil, false
	}
	return session, true
}

func (s *sessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}
