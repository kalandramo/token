package store

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalandramo/token/core"
)

func TestInMemoryStore_Get(t *testing.T) {
	store := NewInMemoryStore()
	token := "test-token"
	data := &core.RefreshTokenData{
		UserData: map[string]any{"user_id": "123"},
		Expiry:   time.Now().Add(1 * time.Hour),
		Created:  time.Now(),
	}

	store.Set(token, data)

	got, err := store.Get(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	uid, ok := got.UserData.(map[string]any)["user_id"]
	if !ok || uid != "123" {
		t.Errorf("user_id mismatch: got %v", got.UserData)
	}
}

func TestInMemoryStore_Get_NotFound(t *testing.T) {
	store := NewInMemoryStore()

	_, err := store.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestInMemoryStore_Get_Expired(t *testing.T) {
	store := NewInMemoryStore()
	token := "expired-token"
	data := &core.RefreshTokenData{
		UserData: map[string]any{"user_id": "123"},
		Expiry:   time.Now().Add(-1 * time.Hour),
		Created:  time.Now().Add(-2 * time.Hour),
	}

	store.Set(token, data)

	_, err := store.Get(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestInMemoryStore_Set(t *testing.T) {
	store := NewInMemoryStore()
	token := "new-token"
	data := &core.RefreshTokenData{
		UserData: "user-data",
		Expiry:   time.Now().Add(1 * time.Hour),
		Created:  time.Now(),
	}

	store.Set(token, data)

	got, err := store.Get(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserData != data.UserData {
		t.Errorf("UserData mismatch: got %v, want %v", got.UserData, data.UserData)
	}
}

func TestInMemoryStore_Remove(t *testing.T) {
	store := NewInMemoryStore()
	token := "remove-me"
	data := &core.RefreshTokenData{
		UserData: "user-data",
		Expiry:   time.Now().Add(1 * time.Hour),
		Created:  time.Now(),
	}

	store.Set(token, data)

	err := store.Remove(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = store.Get(token)
	if err == nil {
		t.Fatal("expected error after removing token")
	}
}

func TestInMemoryStore_Remove_NotFound(t *testing.T) {
	store := NewInMemoryStore()

	err := store.Remove("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}
}

func TestInMemoryStore_Cleanup(t *testing.T) {
	store := NewInMemoryStore()

	store.Set("valid", &core.RefreshTokenData{
		UserData: "valid",
		Expiry:   time.Now().Add(1 * time.Hour),
		Created:  time.Now(),
	})

	store.Set("expired", &core.RefreshTokenData{
		UserData: "expired",
		Expiry:   time.Now().Add(-1 * time.Hour),
		Created:  time.Now().Add(-2 * time.Hour),
	})

	store.Cleanup()

	if _, err := store.Get("valid"); err != nil {
		t.Errorf("valid token should still exist: %v", err)
	}

	_, err := store.Get("expired")
	if err == nil {
		t.Fatal("expected error for cleaned up token")
	}
}

func TestInMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewInMemoryStore()
	done := make(chan bool)
	var counter atomic.Int64

	go func() {
		for range 100 {
			v := counter.Add(1)
			token := string(rune(v))
			store.Set(token, &core.RefreshTokenData{
				UserData: "concurrent",
				Expiry:   time.Now().Add(1 * time.Hour),
				Created:  time.Now(),
			})
		}
		done <- true
	}()

	go func() {
		for range 100 {
			store.Get("test")
		}
		done <- true
	}()

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
