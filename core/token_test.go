package core_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kalandramo/token/core"
)

func TestToken_JSONSerialization(t *testing.T) {
	now := time.Now().Unix()
	token := &core.Token{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    now + 3600,
		CreatedAt:    now,
	}

	data, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("failed to marshal token: %v", err)
	}

	var decoded core.Token
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal token: %v", err)
	}

	if decoded.AccessToken != token.AccessToken {
		t.Errorf("AccessToken mismatch: got %q, want %q", decoded.AccessToken, token.AccessToken)
	}
	if decoded.TokenType != token.TokenType {
		t.Errorf("TokenType mismatch: got %q, want %q", decoded.TokenType, token.TokenType)
	}
	if decoded.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken mismatch: got %q, want %q", decoded.RefreshToken, token.RefreshToken)
	}
	if decoded.ExpiresAt != token.ExpiresAt {
		t.Errorf("ExpiresAt mismatch: got %d, want %d", decoded.ExpiresAt, token.ExpiresAt)
	}
	if decoded.CreatedAt != token.CreatedAt {
		t.Errorf("CreatedAt mismatch: got %d, want %d", decoded.CreatedAt, token.CreatedAt)
	}
}

func TestToken_DefaultTokenType(t *testing.T) {
	token := &core.Token{
		AccessToken:  "test",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		ExpiresAt:    3600,
		CreatedAt:    1000,
	}

	if token.TokenType != "Bearer" {
		t.Errorf("expected default TokenType to be 'Bearer', got %q", token.TokenType)
	}
}

func TestRefreshTokenData_JSONSerialization(t *testing.T) {
	now := time.Now()
	createdAt := now.Add(-time.Hour)
	data := &core.RefreshTokenData{
		UserData: map[string]any{"user_id": "12345", "role": "admin"},
		Expiry:   now.Add(24 * time.Hour),
		Created:  createdAt,
	}

	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal RefreshTokenData: %v", err)
	}

	var decoded core.RefreshTokenData
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("failed to unmarshal RefreshTokenData: %v", err)
	}

	originalMap, ok := data.UserData.(map[string]any)
	if !ok {
		t.Fatal("original UserData is not map[string]any")
	}
	decodedMap, ok := decoded.UserData.(map[string]any)
	if !ok {
		t.Fatal("decoded UserData is not map[string]any")
	}

	if decodedMap["user_id"] != originalMap["user_id"] {
		t.Errorf("user_id mismatch: got %v, want %v", decodedMap["user_id"], originalMap["user_id"])
	}
	if decodedMap["role"] != originalMap["role"] {
		t.Errorf("role mismatch: got %v, want %v", decodedMap["role"], originalMap["role"])
	}
}
