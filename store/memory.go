package store

import (
	"errors"
	"sync"
	"time"

	"github.com/kalandramo/token/core"
)

// ErrInvalidToken is returned when a refresh token is not found or has expired.
var ErrInvalidToken = errors.New("refresh token is invalid")

// InMemoryRefreshTokenStore is a thread-safe in-memory refresh token store.
type InMemoryRefreshTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*core.RefreshTokenData
}

// NewInMemoryStore creates a new InMemoryRefreshTokenStore.
func NewInMemoryStore() *InMemoryRefreshTokenStore {
	return &InMemoryRefreshTokenStore{
		tokens: make(map[string]*core.RefreshTokenData),
	}
}

// Get returns the RefreshTokenData associated with the given refresh token.
// Returns ErrInvalidToken if the token does not exist or has expired.
func (s *InMemoryRefreshTokenStore) Get(token string) (*core.RefreshTokenData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, ok := s.tokens[token]
	if !ok {
		return nil, ErrInvalidToken
	}

	if time.Now().After(data.Expiry) {
		return nil, ErrInvalidToken
	}

	return data, nil
}

// Set stores the RefreshTokenData with the given refresh token as key.
func (s *InMemoryRefreshTokenStore) Set(token string, data *core.RefreshTokenData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token] = data
	return nil
}

// Remove deletes the RefreshTokenData associated with the given refresh token.
func (s *InMemoryRefreshTokenStore) Remove(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tokens[token]; !ok {
		return ErrInvalidToken
	}

	delete(s.tokens, token)
	return nil
}

// Cleanup removes expired refresh tokens from storage.
func (s *InMemoryRefreshTokenStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for token, data := range s.tokens {
		if now.After(data.Expiry) {
			delete(s.tokens, token)
		}
	}
}
