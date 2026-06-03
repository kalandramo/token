package store

import (
	"testing"
)

func TestDefault(t *testing.T) {
	store := Default()
	if store == nil {
		t.Fatal("Default() returned nil")
	}
	if _, ok := store.(*InMemoryRefreshTokenStore); !ok {
		t.Errorf("Default() should return *InMemoryRefreshTokenStore, got %T", store)
	}
}

func TestNewStore_Memory(t *testing.T) {
	store, err := NewStore(&Config{Type: "memory"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := store.(*InMemoryRefreshTokenStore); !ok {
		t.Errorf("expected *InMemoryRefreshTokenStore, got %T", store)
	}
}

func TestNewStore_EmptyType(t *testing.T) {
	store, err := NewStore(&Config{Type: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := store.(*InMemoryRefreshTokenStore); !ok {
		t.Errorf("expected *InMemoryRefreshTokenStore for empty type, got %T", store)
	}
}

func TestNewStore_NilConfig(t *testing.T) {
	_, err := NewStore(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestNewStore_UnsupportedType(t *testing.T) {
	_, err := NewStore(&Config{Type: "invalid"})
	if err == nil {
		t.Fatal("expected error for unsupported store type")
	}
}

func TestNewStore_Redis_NoConfig(t *testing.T) {
	_, err := NewStore(&Config{Type: "redis"})
	if err == nil {
		t.Fatal("expected error for redis type without redis config")
	}
}

func TestMustNewStore(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustNewStore() panicked unexpectedly: %v", r)
		}
	}()

	store := MustNewStore(&Config{Type: "memory"})
	if store == nil {
		t.Fatal("MustNewStore() returned nil")
	}
}

func TestMustNewStore_PanicsOnError(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustNewStore() should panic for nil config")
		}
	}()

	_ = MustNewStore(nil)
}

func TestNewMemoryStore(t *testing.T) {
	store := NewMemoryStore()
	if store == nil {
		t.Fatal("NewMemoryStore() returned nil")
	}
	if _, ok := store.(*InMemoryRefreshTokenStore); !ok {
		t.Errorf("expected *InMemoryRefreshTokenStore, got %T", store)
	}
}
