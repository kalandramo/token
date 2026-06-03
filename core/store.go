// Package core provides the core data models for the gin-jwt library.
package core

import (
	"time"
)

// TokenStore is the interface that wraps the basic methods for a refresh token storage.
type TokenStore interface {
	// Get returns the RefreshTokenData associated with the given refresh token string.
	Get(string) (*RefreshTokenData, error)
	// Set stores the RefreshTokenData with the given refresh token string as key.
	Set(string, *RefreshTokenData)
	// Remove deletes the RefreshTokenData associated with the given refresh token string.
	Remove(string) error
	// Cleanup removes expired refresh tokens from storage.
	Cleanup()
}

// Token represents a pair of access and refresh tokens returned by login or refresh.
type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_in"`
	CreatedAt    int64  `json:"created_at"`
}

// RefreshTokenData is the data stored and retrieved from the TokenStore for each refresh token.
type RefreshTokenData struct {
	UserData any       `json:"user_data"`
	Expiry   time.Time `json:"expiry"`
	Created  time.Time `json:"created"`
}
