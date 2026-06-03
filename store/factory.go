package store

import (
	"fmt"

	"github.com/kalandramo/token/core"
)

// Config holds the configuration for creating a TokenStore.
type Config struct {
	// Type is the storage backend type: "memory" or "redis".
	Type string
	// Redis contains Redis-specific configuration when Type is "redis".
	Redis *RedisConfig
}

// Default returns a new InMemoryRefreshTokenStore with default settings.
func Default() core.TokenStore {
	return NewInMemoryStore()
}

// NewStore creates a TokenStore based on the provided Config.
// Currently only supports "memory" type.
func NewStore(config *Config) (core.TokenStore, error) {
	if config == nil {
		return nil, fmt.Errorf("store config is required")
	}

	switch config.Type {
	case "memory", "":
		return NewInMemoryStore(), nil
	case "redis":
		if config.Redis == nil {
			return nil, fmt.Errorf("redis config is required for redis store type")
		}
		return NewRedisStore(config.Redis)
	default:
		return nil, fmt.Errorf("unsupported store type: %s", config.Type)
	}
}

// MustNewStore is like NewStore but panics if the store cannot be created.
func MustNewStore(config *Config) core.TokenStore {
	store, err := NewStore(config)
	if err != nil {
		panic(fmt.Sprintf("store factory: %v", err))
	}
	return store
}

// NewMemoryStore creates a new InMemoryRefreshTokenStore.
func NewMemoryStore() core.TokenStore {
	return NewInMemoryStore()
}
