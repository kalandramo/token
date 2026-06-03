package store

import (
	"time"

	"github.com/kalandramo/token/core"
)

// RedisConfig holds the configuration for Redis refresh token store.
type RedisConfig struct {
	Addr            string        `json:"addr"`
	Password        string        `json:"password"`
	DB              int           `json:"db"`
	CacheSize       int           `json:"cache_size"`
	CacheTTL        time.Duration `json:"cache_ttl"`
	PoolSize        int           `json:"pool_size"`
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time"`
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
	KeyPrefix       string        `json:"key_prefix"`
}

// NewRedisStore creates a RedisRefreshTokenStore with the given config.
// TODO: Full implementation in issue #3.
func NewRedisStore(config *RedisConfig) (core.TokenStore, error) {
	return nil, nil
}

// MustNewRedisStore is like NewRedisStore but panics on error.
// TODO: Full implementation in issue #3.
func MustNewRedisStore(config *RedisConfig) core.TokenStore {
	return nil
}
