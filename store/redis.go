package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/kalandramo/token/core"
	"github.com/redis/rueidis"
)

const (
	defaultConnectTimeout = 5 * time.Second
	defaultReadTimeout    = 3 * time.Second
	defaultWriteTimeout   = 3 * time.Second
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

// RedisRefreshTokenStore is a Redis-backed refresh token store using rueidis.
type RedisRefreshTokenStore struct {
	client    rueidis.Client
	keyPrefix string
	cacheTTL  time.Duration
}

// NewRedisStore creates a RedisRefreshTokenStore with the given config.
func NewRedisStore(config *RedisConfig) (core.TokenStore, error) {
	config.applyDefaults()

	opt := rueidis.ClientOption{
		InitAddress:       []string{config.Addr},
		Password:          config.Password,
		SelectDB:          config.DB,
		CacheSizeEachConn: config.CacheSize,
		BlockingPoolSize:  config.PoolSize,
		Dialer: net.Dialer{
			Timeout:   defaultConnectTimeout,
			KeepAlive: config.ConnMaxIdleTime,
		},
	}

	client, err := rueidis.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("failed to create redis client: %w", err)
	}

	return &RedisRefreshTokenStore{
		client:    client,
		keyPrefix: config.KeyPrefix,
		cacheTTL:  config.CacheTTL,
	}, nil
}

// MustNewRedisStore is like NewRedisStore but panics on error.
func MustNewRedisStore(config *RedisConfig) core.TokenStore {
	store, err := NewRedisStore(config)
	if err != nil {
		panic(fmt.Sprintf("redis store: %v", err))
	}
	return store
}

// Get returns the RefreshTokenData associated with the given refresh token.
// Uses client-side cache via DoCache(), falls back to Redis on cache miss.
func (s *RedisRefreshTokenStore) Get(token string) (*core.RefreshTokenData, error) {
	key := s.keyPrefix + token

	ctx, cancel := context.WithTimeout(context.Background(), defaultReadTimeout)
	defer cancel()

	cmd := s.client.B().Get().Key(key).Cache()
	result := s.client.DoCache(ctx, cmd, s.cacheTTL)

	// Check for cache errors
	if err := result.NonRedisError(); err != nil {
		// Cache miss or error - try direct GET
		if err == rueidis.ErrDoCacheAborted || err.Error() == "ERR no such key" {
			return s.getDirect(ctx, key)
		}
		// Other cache errors - try direct GET as fallback
		return s.getDirect(ctx, key)
	}

	b, err := result.AsBytes()
	if err != nil {
		errStr := err.Error()
		if errStr == "ERR no such key" || errStr == "redis nil message" {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("redis get cache: %w", err)
	}

	return s.parseTokenData(b)
}

// getDirect performs a direct GET without caching.
func (s *RedisRefreshTokenStore) getDirect(ctx context.Context, key string) (*core.RefreshTokenData, error) {
	result := s.client.Do(ctx, s.client.B().Get().Key(key).Build())

	b, err := result.AsBytes()
	if err != nil {
		if err.Error() == "ERR no such key" {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("redis get direct: %w", err)
	}

	return s.parseTokenData(b)
}

// parseTokenData parses JSON data into RefreshTokenData and checks expiry.
func (s *RedisRefreshTokenStore) parseTokenData(b []byte) (*core.RefreshTokenData, error) {
	var data core.RefreshTokenData
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("redis parse json: %w", err)
	}

	if time.Now().After(data.Expiry) {
		return nil, ErrInvalidToken
	}

	return &data, nil
}

// Set stores the RefreshTokenData in Redis with TTL based on Expiry.
// Returns an error if the operation fails.
func (s *RedisRefreshTokenStore) Set(token string, data *core.RefreshTokenData) error {
	key := s.keyPrefix + token

	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis set marshal: %w", err)
	}

	seconds := int(time.Until(data.Expiry).Seconds())
	if seconds < 1 {
		seconds = 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultWriteTimeout)
	defer cancel()

	result := s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(body)).ExSeconds(int64(seconds)).Build())
	if err := result.Error(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}

	return nil
}

// Remove deletes the refresh token from Redis.
// Returns ErrInvalidToken if the token does not exist.
func (s *RedisRefreshTokenStore) Remove(token string) error {
	key := s.keyPrefix + token

	ctx, cancel := context.WithTimeout(context.Background(), defaultWriteTimeout)
	defer cancel()

	result := s.client.Do(ctx, s.client.B().Del().Key(key).Build())
	count, err := result.AsInt64()
	if err != nil {
		return fmt.Errorf("redis remove: %w", err)
	}
	if count == 0 {
		return ErrInvalidToken
	}
	return nil
}

// Cleanup removes expired refresh tokens using SCAN + GET.
func (s *RedisRefreshTokenStore) Cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cursor := uint64(0)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cmd := s.client.B().Scan().Cursor(cursor).Match(s.keyPrefix + "*").Count(100).Build()
		res := s.client.Do(ctx, cmd)

		arr, err := res.AsStrSlice()
		if err != nil {
			return
		}
		if len(arr) < 1 {
			return
		}

		// First element is the next cursor
		nextCursor, err := strconv.ParseUint(arr[0], 10, 64)
		if err != nil {
			return
		}

		// Remaining elements are keys
		if len(arr) > 1 {
			keys := arr[1:]
			s.cleanupKeys(ctx, keys)
		}

		if nextCursor == 0 {
			break
		}
		cursor = nextCursor
	}
}

// cleanupKeys checks and removes expired tokens from the given keys.
func (s *RedisRefreshTokenStore) cleanupKeys(ctx context.Context, keys []string) {
	for _, k := range keys {
		val := s.client.Do(ctx, s.client.B().Get().Key(k).Build())
		b, err := val.AsBytes()
		if err != nil {
			// Key doesn't exist or error - delete it
			s.client.Do(ctx, s.client.B().Del().Key(k).Build())
			continue
		}

		var result core.RefreshTokenData
		if err := json.Unmarshal(b, &result); err != nil {
			// Invalid data - delete it
			s.client.Do(ctx, s.client.B().Del().Key(k).Build())
			continue
		}

		if time.Now().After(result.Expiry) {
			s.client.Do(ctx, s.client.B().Del().Key(k).Build())
		}
	}
}

// IsAvailable checks whether the Redis connection is healthy.
func (s *RedisRefreshTokenStore) IsAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := s.client.Do(ctx, s.client.B().Ping().Build()).Error()
	return err == nil
}

// Close closes the underlying Redis client connection.
func (s *RedisRefreshTokenStore) Close() {
	if s.client == nil {
		return
	}
	s.client.Close()
}

// --- Functional Options ---

// WithRedisAddr sets the Redis address.
func WithRedisAddr(addr string) func(*RedisConfig) {
	return func(c *RedisConfig) { c.Addr = addr }
}

// WithRedisAuth sets the Redis password and database number.
func WithRedisAuth(password string, db int) func(*RedisConfig) {
	return func(c *RedisConfig) {
		c.Password = password
		c.DB = db
	}
}

// WithRedisCache sets the client-side cache size and TTL.
func WithRedisCache(size int, ttl time.Duration) func(*RedisConfig) {
	return func(c *RedisConfig) {
		c.CacheSize = size
		c.CacheTTL = ttl
	}
}

// WithRedisPool sets the connection pool size and idle/lifetime settings.
func WithRedisPool(poolSize int, maxIdleTime, maxLifetime time.Duration) func(*RedisConfig) {
	return func(c *RedisConfig) {
		c.PoolSize = poolSize
		c.ConnMaxIdleTime = maxIdleTime
		c.ConnMaxLifetime = maxLifetime
	}
}

// WithRedisKeyPrefix sets the Redis key prefix.
func WithRedisKeyPrefix(prefix string) func(*RedisConfig) {
	return func(c *RedisConfig) { c.KeyPrefix = prefix }
}

// WithRedisTLS is a placeholder for TLS configuration.
// TODO: Add *tls.Config field to RedisConfig and wire it in NewClient.
func WithRedisTLS(_ interface{}) func(*RedisConfig) {
	return func(c *RedisConfig) {}
}

// ApplyOptions applies functional options to the RedisConfig.
func (c *RedisConfig) ApplyOptions(opts ...func(*RedisConfig)) {
	for _, opt := range opts {
		opt(c)
	}
}

// applyDefaults sets default values per SPEC §6.2.
func (c *RedisConfig) applyDefaults() {
	if c.Addr == "" {
		c.Addr = "localhost:6379"
	}
	if c.CacheSize == 0 {
		c.CacheSize = 128 * 1024 * 1024 // 128MB
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = 1 * time.Minute
	}
	if c.PoolSize == 0 {
		c.PoolSize = 10
	}
	if c.ConnMaxIdleTime == 0 {
		c.ConnMaxIdleTime = 30 * time.Minute
	}
	if c.ConnMaxLifetime == 0 {
		c.ConnMaxLifetime = 1 * time.Hour
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = "gin-jwt:"
	}
}
