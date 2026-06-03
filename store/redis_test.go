package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/kalandramo/token/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	redismod "github.com/testcontainers/testcontainers-go/modules/redis"
)

// startRedisContainer 启动一个 Redis 测试容器，测试结束后自动清理。
func startRedisContainer(t *testing.T) *redismod.RedisContainer {
	t.Helper()

	container, err := redismod.Run(
		context.Background(),
		"redis:alpine",
	)
	require.NoError(t, err, "failed to start Redis container")

	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Logf("failed to terminate Redis container: %s", err)
		}
	})

	return container
}

// redisConnAddr 获取容器的连接地址。
func redisConnAddr(t *testing.T, container *redismod.RedisContainer) string {
	t.Helper()

	host, err := container.Host(context.Background())
	require.NoError(t, err)

	port, err := container.MappedPort(context.Background(), "6379")
	require.NoError(t, err)

	return fmt.Sprintf("%s:%s", host, port.Port())
}

func TestRedisConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name   string
		config *RedisConfig
		want   *RedisConfig
	}{
		{
			name:   "empty config gets all defaults",
			config: &RedisConfig{},
			want: &RedisConfig{
				Addr:            "localhost:6379",
				DB:              0,
				CacheSize:       128 * 1024 * 1024,
				CacheTTL:        1 * time.Minute,
				PoolSize:        10,
				ConnMaxIdleTime: 30 * time.Minute,
				ConnMaxLifetime: 1 * time.Hour,
				KeyPrefix:       "gin-jwt:",
			},
		},
		{
			name: "partial config keeps provided values",
			config: &RedisConfig{
				Addr:      "my-redis:6380",
				Password:  "secret",
				KeyPrefix: "myapp:",
			},
			want: &RedisConfig{
				Addr:            "my-redis:6380",
				Password:        "secret",
				DB:              0,
				CacheSize:       128 * 1024 * 1024,
				CacheTTL:        1 * time.Minute,
				PoolSize:        10,
				ConnMaxIdleTime: 30 * time.Minute,
				ConnMaxLifetime: 1 * time.Hour,
				KeyPrefix:       "myapp:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.applyDefaults()
			if tt.config.Addr != tt.want.Addr {
				t.Errorf("Addr = %q, want %q", tt.config.Addr, tt.want.Addr)
			}
			if tt.config.KeyPrefix != tt.want.KeyPrefix {
				t.Errorf("KeyPrefix = %q, want %q", tt.config.KeyPrefix, tt.want.KeyPrefix)
			}
			if tt.config.CacheSize != tt.want.CacheSize {
				t.Errorf("CacheSize = %d, want %d", tt.config.CacheSize, tt.want.CacheSize)
			}
		})
	}
}

func TestFunctionalOptions(t *testing.T) {
	config := &RedisConfig{}
	config.ApplyOptions(
		WithRedisAddr("custom:6380"),
		WithRedisAuth("mypass", 2),
		WithRedisCache(256*1024*1024, 5*time.Minute),
		WithRedisPool(20, 1*time.Hour, 2*time.Hour),
		WithRedisKeyPrefix("test:"),
	)

	if config.Addr != "custom:6380" {
		t.Errorf("Addr = %q, want %q", config.Addr, "custom:6380")
	}
	if config.Password != "mypass" {
		t.Errorf("Password = %q, want %q", config.Password, "mypass")
	}
	if config.DB != 2 {
		t.Errorf("DB = %d, want %d", config.DB, 2)
	}
	if config.CacheSize != 256*1024*1024 {
		t.Errorf("CacheSize = %d, want %d", config.CacheSize, 256*1024*1024)
	}
	if config.CacheTTL != 5*time.Minute {
		t.Errorf("CacheTTL = %v, want %v", config.CacheTTL, 5*time.Minute)
	}
	if config.PoolSize != 20 {
		t.Errorf("PoolSize = %d, want %d", config.PoolSize, 20)
	}
	if config.KeyPrefix != "test:" {
		t.Errorf("KeyPrefix = %q, want %q", config.KeyPrefix, "test:")
	}
}

func TestNewRedisStore_ConnectionFailure(t *testing.T) {
	config := &RedisConfig{
		Addr: "invalid-host-that-does-not-exist:99999",
	}

	store, err := NewRedisStore(config)
	if err == nil {
		t.Fatal("expected error for invalid redis address")
	}
	if store != nil {
		t.Error("expected nil store on connection failure")
	}
}

// --- Integration tests with real Redis container ---

func TestRedisStore_TokenOperations(t *testing.T) {
	container := startRedisContainer(t)
	addr := redisConnAddr(t, container)

	config := &RedisConfig{
		Addr:      addr,
		KeyPrefix: "test-token-",
		CacheTTL:  100 * time.Millisecond,
	}

	store, err := NewRedisStore(config)
	require.NoError(t, err)
	defer store.(*RedisRefreshTokenStore).Close()

	token := "test-refresh-token"
	data := &core.RefreshTokenData{
		UserData: map[string]any{"user_id": "12345", "role": "admin"},
		Expiry:   time.Now().Add(24 * time.Hour),
		Created:  time.Now(),
	}

	// Test Set
	require.NoError(t, store.Set(token, data))

	// Test Get
	got, err := store.Get(token)
	require.NoError(t, err)
	require.NotNil(t, got.UserData)

	// Test Remove
	require.NoError(t, store.Remove(token))

	// Wait for client-side cache to expire before verifying removal
	time.Sleep(150 * time.Millisecond)

	_, err = store.Get(token)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestRedisStore_ExpiredToken(t *testing.T) {
	container := startRedisContainer(t)
	addr := redisConnAddr(t, container)

	config := &RedisConfig{
		Addr:      addr,
		KeyPrefix: "test-expired-",
	}

	store, err := NewRedisStore(config)
	require.NoError(t, err)
	defer store.(*RedisRefreshTokenStore).Close()

	token := "expired-test-token"
	data := &core.RefreshTokenData{
		UserData: "user-data",
		Expiry:   time.Now().Add(-1 * time.Hour),
		Created:  time.Now().Add(-2 * time.Hour),
	}

	require.NoError(t, store.Set(token, data))

	_, err = store.Get(token)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestRedisStore_Cleanup(t *testing.T) {
	container := startRedisContainer(t)
	addr := redisConnAddr(t, container)

	config := &RedisConfig{
		Addr:      addr,
		KeyPrefix: "test-cleanup-",
	}

	store, err := NewRedisStore(config)
	require.NoError(t, err)
	defer store.(*RedisRefreshTokenStore).Close()

	// Set valid token
	require.NoError(t, store.Set("valid-token", &core.RefreshTokenData{
		UserData: "valid",
		Expiry:   time.Now().Add(1 * time.Hour),
		Created:  time.Now(),
	}))

	// Set expired tokens
	require.NoError(t, store.Set("expired-token-1", &core.RefreshTokenData{
		UserData: "expired1",
		Expiry:   time.Now().Add(-1 * time.Hour),
		Created:  time.Now().Add(-2 * time.Hour),
	}))
	require.NoError(t, store.Set("expired-token-2", &core.RefreshTokenData{
		UserData: "expired2",
		Expiry:   time.Now().Add(-2 * time.Hour),
		Created:  time.Now().Add(-3 * time.Hour),
	}))

	// Run cleanup
	store.Cleanup()

	// Verify valid token still exists
	_, err = store.Get("valid-token")
	assert.NoError(t, err, "valid token should still exist")

	// Verify expired tokens are removed
	_, err = store.Get("expired-token-1")
	assert.ErrorIs(t, err, ErrInvalidToken, "expired-token-1 should be removed")

	_, err = store.Get("expired-token-2")
	assert.ErrorIs(t, err, ErrInvalidToken, "expired-token-2 should be removed")
}

func TestRedisStore_ConcurrentAccess(t *testing.T) {
	container := startRedisContainer(t)
	addr := redisConnAddr(t, container)

	config := &RedisConfig{
		Addr:      addr,
		KeyPrefix: "test-concurrent-",
	}

	store, err := NewRedisStore(config)
	require.NoError(t, err)
	defer store.(*RedisRefreshTokenStore).Close()

	// Pre-populate tokens
	for i := 0; i < 10; i++ {
		store.Set(fmt.Sprintf("token-%d", i), &core.RefreshTokenData{
			UserData: "concurrent",
			Expiry:   time.Now().Add(1 * time.Hour),
			Created:  time.Now(),
		})
	}

	done := make(chan bool, 3)

	// Writer goroutine
	go func() {
		for range 100 {
			for i := 0; i < 10; i++ {
				store.Set(fmt.Sprintf("token-%d", i), &core.RefreshTokenData{
					UserData: fmt.Sprintf("user-%d", i),
					Expiry:   time.Now().Add(1 * time.Hour),
					Created:  time.Now(),
				})
			}
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for range 100 {
			for i := 0; i < 10; i++ {
				store.Get(fmt.Sprintf("token-%d", i))
			}
		}
		done <- true
	}()

	// Cleanup goroutine
	go func() {
		for range 10 {
			store.Cleanup()
		}
		done <- true
	}()

	for range 3 {
		<-done
	}
}

func TestRedisStore_IsAvailable(t *testing.T) {
	container := startRedisContainer(t)
	addr := redisConnAddr(t, container)

	config := &RedisConfig{Addr: addr}
	store, err := NewRedisStore(config)
	require.NoError(t, err)
	defer store.(*RedisRefreshTokenStore).Close()

	assert.True(t, store.(*RedisRefreshTokenStore).IsAvailable())
}

func TestMustNewRedisStore(t *testing.T) {
	container := startRedisContainer(t)
	addr := redisConnAddr(t, container)

	config := &RedisConfig{Addr: addr}
	store := MustNewRedisStore(config)
	assert.NotNil(t, store)
}

func TestMustNewRedisStore_PanicOnError(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid config")
		}
	}()

	config := &RedisConfig{
		Addr: "127.0.0.1:1",
	}

	_ = MustNewRedisStore(config)
}

func TestRedisStore_Get_CachePath(t *testing.T) {
	container := startRedisContainer(t)
	addr := redisConnAddr(t, container)

	config := &RedisConfig{
		Addr:      addr,
		CacheTTL:  5 * time.Second,
		KeyPrefix: "test-cache-",
	}

	store, err := NewRedisStore(config)
	require.NoError(t, err)
	defer store.(*RedisRefreshTokenStore).Close()

	token := "cache-test-token"
	data := &core.RefreshTokenData{
		UserData: map[string]any{"test": "value"},
		Expiry:   time.Now().Add(1 * time.Hour),
		Created:  time.Now(),
	}

	require.NoError(t, store.Set(token, data))

	// First Get
	got, err := store.Get(token)
	require.NoError(t, err)
	require.NotNil(t, got.UserData)

	// Second Get (should use cache)
	got2, err := store.Get(token)
	require.NoError(t, err)
	require.NotNil(t, got2.UserData)
}

func TestRedisStore_Remove_NotFound(t *testing.T) {
	container := startRedisContainer(t)
	addr := redisConnAddr(t, container)

	config := &RedisConfig{
		Addr:      addr,
		KeyPrefix: "test-remove-notfound-",
	}

	store, err := NewRedisStore(config)
	require.NoError(t, err)
	defer store.(*RedisRefreshTokenStore).Close()

	err = store.Remove("nonexistent-token")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestRedisStore_WithCustomPrefix(t *testing.T) {
	container := startRedisContainer(t)
	addr := redisConnAddr(t, container)

	config := &RedisConfig{
		Addr:      addr,
		KeyPrefix: "custom:prefix:",
	}

	store, err := NewRedisStore(config)
	require.NoError(t, err)
	defer store.(*RedisRefreshTokenStore).Close()

	token := "prefixed-token"
	data := &core.RefreshTokenData{
		UserData: "prefixed-data",
		Expiry:   time.Now().Add(1 * time.Hour),
		Created:  time.Now(),
	}

	require.NoError(t, store.Set(token, data))

	got, err := store.Get(token)
	require.NoError(t, err)
	assert.Equal(t, "prefixed-data", got.UserData)
}

// --- Mock-based unit tests ---

func TestRedisRefreshTokenStore_parseTokenData_Valid(t *testing.T) {
	store := &RedisRefreshTokenStore{}

	now := time.Now()
	data := &core.RefreshTokenData{
		UserData: map[string]any{"user_id": "123"},
		Expiry:   now.Add(1 * time.Hour),
		Created:  now,
	}

	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	got, err := store.parseTokenData(jsonData)
	require.NoError(t, err)
	assert.NotNil(t, got.UserData)
}

func TestRedisRefreshTokenStore_parseTokenData_Expired(t *testing.T) {
	store := &RedisRefreshTokenStore{}

	now := time.Now()
	data := &core.RefreshTokenData{
		UserData: "test",
		Expiry:   now.Add(-1 * time.Hour),
		Created:  now.Add(-2 * time.Hour),
	}

	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	_, err = store.parseTokenData(jsonData)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestRedisRefreshTokenStore_parseTokenData_InvalidJSON(t *testing.T) {
	store := &RedisRefreshTokenStore{}

	_, err := store.parseTokenData([]byte("invalid json"))
	assert.Error(t, err)
}

func TestRedisRefreshTokenStore_Close_NoOp(t *testing.T) {
	store := &RedisRefreshTokenStore{}
	// Close on nil client should not panic
	store.Close()
}
