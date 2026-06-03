package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGinJWTMiddleware_DefaultValues(t *testing.T) {
	m := &GinJWTMiddleware{
		Key: []byte("test-secret"),
	}

	mw, err := New(m)
	require.NoError(t, err)

	assert.Equal(t, "gin jwt", mw.Realm)
	assert.Equal(t, "HS256", mw.SigningAlgorithm)
	assert.Equal(t, time.Hour, mw.Timeout)
	assert.Equal(t, "header:Authorization", mw.TokenLookup)
	assert.Equal(t, "Bearer", mw.TokenHeadName)
	assert.Equal(t, "identity", mw.IdentityKey)
	assert.Equal(t, "exp", mw.ExpField)
	assert.Equal(t, "jwt", mw.CookieName)
	assert.Equal(t, "refresh_token", mw.RefreshTokenCookieName)
	assert.NotNil(t, mw.Authorizer)
	assert.NotNil(t, mw.TimeFunc)
	assert.NotNil(t, mw.RefreshTokenStore)
}

func TestGinJWTMiddleware_CustomValues(t *testing.T) {
	m := &GinJWTMiddleware{
		Realm:                  "test realm",
		SigningAlgorithm:       "HS384",
		Key:                    []byte("another-secret"),
		Timeout:                2 * time.Hour,
		TokenLookup:            "query:token",
		TokenHeadName:          "JWT",
		IdentityKey:            "user_id",
		RefreshTokenTimeout:    7 * 24 * time.Hour,
		RefreshTokenLength:     16,
		CookieName:             "myjwt",
		RefreshTokenCookieName: "my_refresh",
	}

	mw, err := New(m)
	require.NoError(t, err)

	assert.Equal(t, "test realm", mw.Realm)
	assert.Equal(t, "HS384", mw.SigningAlgorithm)
	assert.Equal(t, 2*time.Hour, mw.Timeout)
	assert.Equal(t, "query:token", mw.TokenLookup)
	assert.Equal(t, "JWT", mw.TokenHeadName)
	assert.Equal(t, "user_id", mw.IdentityKey)
	assert.Equal(t, 7*24*time.Hour, mw.RefreshTokenTimeout)
	assert.Equal(t, 16, mw.RefreshTokenLength)
	assert.Equal(t, "myjwt", mw.CookieName)
	assert.Equal(t, "my_refresh", mw.RefreshTokenCookieName)
}

func TestNew_MissingSecretKey(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm: "HS256",
		// Key is missing
	}

	_, err := New(m)
	assert.ErrorIs(t, err, ErrMissingSecretKey)
}

func TestNew_UnsupportedAlgorithm(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm: "ES256",
	}

	_, err := New(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signing algorithm")
}

func TestNew_WithKeyFunc(t *testing.T) {
	m := &GinJWTMiddleware{
		KeyFunc: func(token *jwt.Token) (any, error) {
			return []byte("dynamic-key"), nil
		},
	}

	mw, err := New(m)
	require.NoError(t, err)
	assert.NotNil(t, mw.KeyFunc)
}

func TestGinJWTMiddleware_LoadRSAKeysFromFile(t *testing.T) {
	// 生成测试密钥对
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKey := &privKey.PublicKey

	// 创建临时文件
	privFile, err := os.CreateTemp("", "private-*.pem")
	require.NoError(t, err)
	defer os.Remove(privFile.Name())

	pubFile, err := os.CreateTemp("", "public-*.pem")
	require.NoError(t, err)
	defer os.Remove(pubFile.Name())

	// 写入私钥
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509MarshalPrivateKey(privKey),
	})
	_, err = privFile.Write(privBytes)
	require.NoError(t, err)
	privFile.Close()

	// 写入公钥
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509MarshalPKIXPublicKey(pubKey),
	})
	_, err = pubFile.Write(pubBytes)
	require.NoError(t, err)
	pubFile.Close()

	m := &GinJWTMiddleware{
		SigningAlgorithm: "RS256",
		PrivKeyFile:      privFile.Name(),
		PubKeyFile:       pubFile.Name(),
	}

	mw, err := New(m)
	require.NoError(t, err)
	assert.NotNil(t, mw.privKey)
	assert.NotNil(t, mw.pubKey)
}

func TestGinJWTMiddleware_LoadRSAKeysFromBytes(t *testing.T) {
	// 生成测试密钥对
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKey := &privKey.PublicKey

	// 序列化为 PEM
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509MarshalPrivateKey(privKey),
	})
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509MarshalPKIXPublicKey(pubKey),
	})

	m := &GinJWTMiddleware{
		SigningAlgorithm: "RS256",
		PrivKeyBytes:     privBytes,
		PubKeyBytes:      pubBytes,
	}

	mw, err := New(m)
	require.NoError(t, err)
	assert.NotNil(t, mw.privKey)
	assert.NotNil(t, mw.pubKey)
}

func TestGinJWTMiddleware_ParseTokenString_HS256(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm: "HS256",
		Key:              []byte("test-secret"),
		TimeFunc:         time.Now,
	}

	mw, err := New(m)
	require.NoError(t, err)

	// 创建一个测试令牌
	claims := jwt.MapClaims{
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iat":  time.Now().Unix(),
		"user": "test-user",
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString(mw.Key)
	require.NoError(t, err)

	// 解析令牌
	parsedToken, err := mw.ParseTokenString(tokenString)
	require.NoError(t, err)
	assert.NotNil(t, parsedToken)

	// 验证 claims
	parsedClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, "test-user", parsedClaims["user"])
}

func TestGinJWTMiddleware_ParseTokenString_InvalidSignature(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm: "HS256",
		Key:              []byte("test-secret"),
		TimeFunc:         time.Now,
	}

	mw, err := New(m)
	require.NoError(t, err)

	// 用不同的密钥创建令牌
	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString([]byte("wrong-secret"))
	require.NoError(t, err)

	// 解析应该失败
	_, err = mw.ParseTokenString(tokenString)
	assert.Error(t, err)
}

func TestGinJWTMiddleware_ParseTokenString_ExpiredToken(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm: "HS256",
		Key:              []byte("test-secret"),
		TimeFunc:         time.Now,
	}

	mw, err := New(m)
	require.NoError(t, err)

	// 创建一个已过期的令牌
	claims := jwt.MapClaims{
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)
	tokenString, err := token.SignedString(mw.Key)
	require.NoError(t, err)

	// 解析应该失败（过期）
	_, err = mw.ParseTokenString(tokenString)
	assert.Error(t, err)
}

func TestGinJWTMiddleware_TokenGenerator(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm:    "HS256",
		Key:                 []byte("test-secret"),
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		TimeFunc:            time.Now,
		PayloadFunc: func(data any) jwt.MapClaims {
			return jwt.MapClaims{
				"user_id": "12345",
				"role":    "admin",
			}
		},
	}

	mw, err := New(m)
	require.NoError(t, err)

	// 生成令牌
	ctx := context.Background()
	userData := map[string]any{"user_id": "12345", "username": "testuser"}
	token, err := mw.TokenGenerator(ctx, userData)
	require.NoError(t, err)

	// 验证令牌
	assert.NotNil(t, token)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.NotEmpty(t, token.AccessToken)
	assert.NotEmpty(t, token.RefreshToken)
	assert.Greater(t, token.ExpiresAt, time.Now().Unix())
	assert.Equal(t, time.Now().Unix(), token.CreatedAt)

	// 验证刷新令牌已存储
	refreshData, err := mw.RefreshTokenStore.Get(token.RefreshToken)
	require.NoError(t, err)
	assert.NotNil(t, refreshData)
}

func TestGinJWTMiddleware_TokenGeneratorWithRevocation(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm:    "HS256",
		Key:                 []byte("test-secret"),
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		TimeFunc:            time.Now,
	}

	mw, err := New(m)
	require.NoError(t, err)

	ctx := context.Background()
	userData := map[string]any{"user_id": "12345"}

	// 生成第一个令牌对
	token1, err := mw.TokenGenerator(ctx, userData)
	require.NoError(t, err)

	// 生成新令牌并撤销旧令牌
	token2, err := mw.TokenGeneratorWithRevocation(ctx, userData, token1.RefreshToken)
	require.NoError(t, err)

	// 验证旧令牌已被撤销
	_, err = mw.RefreshTokenStore.Get(token1.RefreshToken)
	assert.Error(t, err)

	// 验证新令牌有效
	_, err = mw.RefreshTokenStore.Get(token2.RefreshToken)
	require.NoError(t, err)
}

func TestGinJWTMiddleware_getAccessTokenTimeout_WithTimeoutFunc(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm: "HS256",
		Key:              []byte("test-secret"),
		Timeout:          time.Hour,
		TimeoutFunc: func(data any) time.Duration {
			return 2 * time.Hour
		},
	}

	mw, err := New(m)
	require.NoError(t, err)

	timeout := mw.getAccessTokenTimeout(nil)
	assert.Equal(t, 2*time.Hour, timeout)
}

func TestGinJWTMiddleware_getRefreshTokenTimeout_WithMaxRefresh(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm:    "HS256",
		Key:                 []byte("test-secret"),
		RefreshTokenTimeout: 30 * 24 * time.Hour,
		MaxRefresh:          7 * 24 * time.Hour,
	}

	mw, err := New(m)
	require.NoError(t, err)

	timeout := mw.getRefreshTokenTimeout()
	assert.Equal(t, 7*24*time.Hour, timeout)
}

func TestGinJWTMiddleware_getRefreshTokenTimeout_NoMaxRefresh(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm:    "HS256",
		Key:                 []byte("test-secret"),
		RefreshTokenTimeout: 30 * 24 * time.Hour,
		MaxRefresh:          0,
	}

	mw, err := New(m)
	require.NoError(t, err)

	timeout := mw.getRefreshTokenTimeout()
	assert.Equal(t, 30*24*time.Hour, timeout)
}

func TestGinJWTMiddleware_ClearSensitiveData(t *testing.T) {
	key := []byte("test-secret-key-12345")
	m := &GinJWTMiddleware{
		SigningAlgorithm: "HS256",
		Key:              append([]byte(nil), key...), // 复制一份
	}

	mw, err := New(m)
	require.NoError(t, err)

	// 保存原始密钥的副本
	originalKey := make([]byte, len(mw.Key))
	copy(originalKey, mw.Key)

	// 清除敏感数据
	mw.ClearSensitiveData()

	// 验证密钥已被清零
	for _, b := range mw.Key {
		assert.Equal(t, byte(0), b)
	}
	assert.NotEqual(t, originalKey, mw.Key)
}

func TestGinJWTMiddleware_StoreFallback(t *testing.T) {
	// 测试当 RefreshTokenStore 未设置时，自动使用内存存储
	m := &GinJWTMiddleware{
		SigningAlgorithm: "HS256",
		Key:              []byte("test-secret"),
	}

	mw, err := New(m)
	require.NoError(t, err)
	assert.NotNil(t, mw.RefreshTokenStore)
	assert.NotNil(t, mw.inMemoryStore)
}

func TestNew_RSAKeysMissingPrivateKey(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm: "RS256",
		// PrivKeyFile and PrivKeyBytes are missing
		PubKeyBytes: []byte("dummy-public-key"),
	}

	_, err := New(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing private key")
}

func TestNew_RSAKeysMissingPublicKey(t *testing.T) {
	// 生成测试私钥
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509MarshalPrivateKey(privKey),
	})

	m := &GinJWTMiddleware{
		SigningAlgorithm: "RS256",
		PrivKeyBytes:     privBytes,
		// PubKeyFile and PubKeyBytes are missing
	}

	_, err = New(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing public key")
}

func TestNew_RSAKeysInvalidPrivateKeyFile(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/nonexistent-key.pem",
		PubKeyFile:       "testdata/public.pem",
	}

	_, err := New(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read private key file")
}

func TestGinJWTMiddleware_TokenGenerator_WithCustomPayloadFunc(t *testing.T) {
	m := &GinJWTMiddleware{
		SigningAlgorithm:    "HS256",
		Key:                 []byte("test-secret"),
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		TimeFunc:            time.Now,
		PayloadFunc: func(data any) jwt.MapClaims {
			return jwt.MapClaims{
				"user_id": "12345",
				"role":    "admin",
				"email":   "test@example.com",
			}
		},
	}

	mw, err := New(m)
	require.NoError(t, err)

	ctx := context.Background()
	userData := map[string]any{"user_id": "12345"}
	token, err := mw.TokenGenerator(ctx, userData)
	require.NoError(t, err)

	// 解析并验证 claims
	parsedToken, err := mw.ParseTokenString(token.AccessToken)
	require.NoError(t, err)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, "12345", claims["user_id"])
	assert.Equal(t, "admin", claims["role"])
	assert.Equal(t, "test@example.com", claims["email"])
}

func TestGinJWTMiddleware_TokenGenerator_WithTimeoutFunc(t *testing.T) {
	customTimeout := 30 * time.Minute
	m := &GinJWTMiddleware{
		SigningAlgorithm: "HS256",
		Key:              []byte("test-secret"),
		Timeout:          time.Hour,
		TimeoutFunc: func(data any) time.Duration {
			return customTimeout
		},
		RefreshTokenTimeout: 24 * time.Hour,
		TimeFunc:            time.Now,
	}

	mw, err := New(m)
	require.NoError(t, err)

	ctx := context.Background()
	userData := map[string]any{"user_id": "12345"}
	token, err := mw.TokenGenerator(ctx, userData)
	require.NoError(t, err)

	// 验证过期时间约为 30 分钟后
	expectedExpiry := time.Now().Add(customTimeout).Unix()
	assert.InDelta(t, expectedExpiry, token.ExpiresAt, 2) // 允许 2 秒误差
}

// 辅助函数：x509 序列化私钥
func x509MarshalPrivateKey(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

// 辅助函数：x509 序列化公钥
func x509MarshalPKIXPublicKey(pub any) []byte {
	bytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return bytes
}
