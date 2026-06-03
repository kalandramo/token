package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kalandramo/token/core"
	"github.com/kalandramo/token/store"
	"github.com/youmark/pkcs8"
)

// ErrMissingSecretKey 表示对称算法缺少密钥
var ErrMissingSecretKey = errors.New("missing secret key for symmetric algorithm")

// ErrMissingPrivateKey 表示 RSA 算法缺少私钥
var ErrMissingPrivateKey = errors.New("missing private key for RSA algorithm")

// ErrMissingPublicKey 表示 RSA 算法缺少公钥
var ErrMissingPublicKey = errors.New("missing public key for RSA algorithm")

// ErrInvalidAlgorithm 表示签名算法与密钥类型不匹配
var ErrInvalidAlgorithm = errors.New("invalid algorithm for key type")

// GinJWTMiddleware 是 JWT 认证中间件的核心结构体
// 包含所有配置项和内部状态
type GinJWTMiddleware struct {
	// 认证域名称，用于 WWW-Authenticate 头
	Realm string

	// 签名算法：HS256/HS384/HS512/RS256/RS384/RS512
	SigningAlgorithm string

	// 对称签名密钥（HS* 系列必需）
	Key []byte

	// 动态密钥函数，设置后 bypass 所有其他 Key 配置
	KeyFunc func(*jwt.Token) (any, error)

	// JWT 访问令牌有效期
	Timeout time.Duration

	// 动态覆盖 Timeout 的回调
	TimeoutFunc func(data any) time.Duration

	// 刷新令牌最大有效时长，0 表示不可刷新
	MaxRefresh time.Duration

	// 用户认证回调（必填）
	Authenticator func(*gin.Context) (any, error)

	// 用户授权回调
	Authorizer func(*gin.Context, any) bool

	// JWT claim 载荷回调
	PayloadFunc func(data any) jwt.MapClaims

	// 认证失败回调
	Unauthorized func(*gin.Context, int, string)

	// 登录响应回调
	LoginResponse func(*gin.Context, *core.Token)

	// 刷新响应回调
	RefreshResponse func(*gin.Context, *core.Token)

	// 登出响应回调
	LogoutResponse func(*gin.Context)

	// 身份提取回调
	IdentityHandler func(*gin.Context) any

	// Context 中存储身份的键名
	IdentityKey string

	// 令牌提取位置，逗号分隔多个来源
	TokenLookup string

	// Header 令牌前缀
	TokenHeadName string

	// 时间函数
	TimeFunc func() time.Time

	// 是否通过 Cookie 发送令牌
	SendCookie bool

	// Cookie 有效期
	CookieMaxAge time.Duration

	// Cookie Secure 标志
	SecureCookie bool

	// Cookie httpOnly 标志
	CookieHTTPOnly bool

	// Cookie SameSite 策略
	CookieSameSite http.SameSite

	// Cookie 域名
	CookieDomain string

	// Cookie 名称
	CookieName string

	// 刷新令牌 Cookie 名称
	RefreshTokenCookieName string

	// 每次响应返回 Authorization 头
	SendAuthorization bool

	// 是否禁用 context.Abort()
	DisabledAbort bool

	// JWT 解析器选项
	ParseOptions []jwt.ParserOption

	// 过期字段名
	ExpField string

	// 刷新令牌有效期
	RefreshTokenTimeout time.Duration

	// 刷新令牌随机字节长度（256 bits）
	RefreshTokenLength int

	// 刷新令牌存储接口
	RefreshTokenStore core.TokenStore

	// 是否启用 Redis 存储
	UseRedisStore bool

	// Redis 配置
	RedisConfig *store.RedisConfig

	// RSA 私钥文件路径
	PrivKeyFile string

	// RSA 私钥字节
	PrivKeyBytes []byte

	// RSA 公钥文件路径
	PubKeyFile string

	// RSA 公钥字节
	PubKeyBytes []byte

	// 私钥密码短语
	PrivateKeyPassphrase string

	// HTTP 错误消息回调
	HTTPStatusMessageFunc func(*gin.Context, error) string

	// 内部：解析后的 RSA 私钥
	privKey *rsa.PrivateKey

	// 内部：解析后的 RSA 公钥
	pubKey *rsa.PublicKey

	// 内部：内存存储（Redis 失败时的降级）
	inMemoryStore *store.InMemoryRefreshTokenStore
}

// New 创建并初始化中间件
// 完成以下初始化：
// 1. 设置默认值
// 2. 加载 RSA 密钥（如果配置了）
// 3. 初始化刷新令牌存储
// 4. 验证算法和密钥配置
func New(m *GinJWTMiddleware) (*GinJWTMiddleware, error) {
	// 设置默认值
	if m.Realm == "" {
		m.Realm = "gin jwt"
	}
	if m.SigningAlgorithm == "" {
		m.SigningAlgorithm = "HS256"
	}
	if m.Timeout == 0 {
		m.Timeout = time.Hour
	}
	if m.TimeFunc == nil {
		m.TimeFunc = time.Now
	}
	if m.TokenLookup == "" {
		m.TokenLookup = "header:Authorization"
	}
	if m.TokenHeadName == "" {
		m.TokenHeadName = "Bearer"
	}
	if m.CookieMaxAge == 0 {
		m.CookieMaxAge = m.Timeout
	}
	if m.IdentityKey == "" {
		m.IdentityKey = "identity"
	}
	if m.ExpField == "" {
		m.ExpField = "exp"
	}
	if m.RefreshTokenTimeout == 0 {
		m.RefreshTokenTimeout = 30 * 24 * time.Hour
	}
	if m.RefreshTokenLength == 0 {
		m.RefreshTokenLength = 32
	}
	if m.CookieName == "" {
		m.CookieName = "jwt"
	}
	if m.RefreshTokenCookieName == "" {
		m.RefreshTokenCookieName = "refresh_token"
	}
	if m.Authorizer == nil {
		m.Authorizer = func(*gin.Context, any) bool { return true }
	}

	// 初始化内存存储（用于 Redis 失败时的降级）
	m.inMemoryStore = store.NewMemoryStore().(*store.InMemoryRefreshTokenStore)

	// 如果启用了 Redis 存储，尝试初始化
	if m.UseRedisStore && m.RedisConfig != nil {
		redisStore, err := store.NewRedisStore(m.RedisConfig)
		if err != nil {
			// Redis 连接失败，降级为内存存储
			m.RefreshTokenStore = m.inMemoryStore
		} else {
			m.RefreshTokenStore = redisStore
		}
	} else {
		// 默认使用内存存储
		if m.RefreshTokenStore == nil {
			m.RefreshTokenStore = m.inMemoryStore
		}
	}

	// 加载 RSA 密钥或验证对称密钥
	if err := m.loadKeys(); err != nil {
		return nil, err
	}

	return m, nil
}

// loadKeys 加载 RSA 密钥或验证对称密钥
func (mw *GinJWTMiddleware) loadKeys() error {
	// 如果设置了 KeyFunc，bypass 所有其他 Key 配置
	if mw.KeyFunc != nil {
		return nil
	}

	// 根据算法类型处理
	switch mw.SigningAlgorithm {
	case "HS256", "HS384", "HS512":
		// 对称算法：检查 Key 是否配置
		if len(mw.Key) == 0 {
			return ErrMissingSecretKey
		}
	case "RS256", "RS384", "RS512":
		// RSA 算法：加载私钥和公钥
		if err := mw.loadRSAKeys(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported signing algorithm: %s", mw.SigningAlgorithm)
	}

	return nil
}

// loadRSAKeys 加载 RSA 私钥和公钥
func (mw *GinJWTMiddleware) loadRSAKeys() error {
	var privKeyBytes []byte
	var pubKeyBytes []byte

	// 优先从文件加载
	if mw.PrivKeyFile != "" {
		data, err := os.ReadFile(mw.PrivKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
		privKeyBytes = data
	} else if len(mw.PrivKeyBytes) > 0 {
		privKeyBytes = make([]byte, len(mw.PrivKeyBytes))
		copy(privKeyBytes, mw.PrivKeyBytes)
	}

	if mw.PubKeyFile != "" {
		data, err := os.ReadFile(mw.PubKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %w", err)
		}
		pubKeyBytes = data
	} else if len(mw.PubKeyBytes) > 0 {
		pubKeyBytes = make([]byte, len(mw.PubKeyBytes))
		copy(pubKeyBytes, mw.PubKeyBytes)
	}

	// 解析私钥
	var err error
	mw.privKey, err = mw.parsePrivateKey(privKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// 解析公钥
	mw.pubKey, err = mw.parsePublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	return nil
}

// parsePrivateKey 解析 RSA 私钥，支持 PKCS8 加密格式
func (mw *GinJWTMiddleware) parsePrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	if len(keyBytes) == 0 {
		return nil, ErrMissingPrivateKey
	}

	// 尝试解析 PKCS8 加密私钥
	if len(mw.PrivateKeyPassphrase) > 0 {
		key, err := pkcs8.ParsePKCS8PrivateKey(keyBytes, []byte(mw.PrivateKeyPassphrase))
		if err == nil {
			if rsaKey, ok := key.(*rsa.PrivateKey); ok {
				// 清零密码短语
				passBytes := []byte(mw.PrivateKeyPassphrase)
				for i := range passBytes {
					passBytes[i] = 0
				}
				return rsaKey, nil
			}
			return nil, ErrMissingPrivateKey
		}
		// PKCS8 解析失败，尝试解析未加密的 PKCS8 私钥
		key, err = pkcs8.ParsePKCS8PrivateKey(keyBytes, nil)
		if err == nil {
			if rsaKey, ok := key.(*rsa.PrivateKey); ok {
				return rsaKey, nil
			}
		}
	}

	// 尝试解析 PKCS1 或 PKCS8 未加密私钥
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		// 尝试作为 PKCS8 未加密私钥解析
		parsedKey, err := pkcs8.ParsePKCS8PrivateKey(keyBytes, nil)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrMissingPrivateKey
		}
	}

	return key, nil
}

// parsePublicKey 解析 RSA 公钥
func (mw *GinJWTMiddleware) parsePublicKey(keyBytes []byte) (*rsa.PublicKey, error) {
	if len(keyBytes) == 0 {
		return nil, ErrMissingPublicKey
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// TokenGenerator 生成令牌对
// 包括访问令牌（JWT）和刷新令牌（随机字节）
func (mw *GinJWTMiddleware) TokenGenerator(ctx context.Context, data any) (*core.Token, error) {
	now := mw.TimeFunc()

	// 生成刷新令牌
	refreshToken, err := mw.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// 创建 JWT claims
	claims := mw.buildClaims(data, now)

	// 生成访问令牌
	accessToken, err := mw.generateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// 计算过期时间
	expiresAt := now.Add(mw.getAccessTokenTimeout(data)).Unix()
	createdAt := now.Unix()

	// 存储刷新令牌
	refreshTokenData := &core.RefreshTokenData{
		UserData: data,
		Expiry:   now.Add(mw.getRefreshTokenTimeout()),
		Created:  now,
	}
	if err := mw.RefreshTokenStore.Set(refreshToken, refreshTokenData); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &core.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		CreatedAt:    createdAt,
	}, nil
}

// TokenGeneratorWithRevocation 生成新令牌并撤销旧刷新令牌
// 用于令牌刷新场景，实现令牌轮换
func (mw *GinJWTMiddleware) TokenGeneratorWithRevocation(ctx context.Context, data any, oldToken string) (*core.Token, error) {
	// 撤销旧刷新令牌
	if err := mw.RefreshTokenStore.Remove(oldToken); err != nil {
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	// 生成新令牌对
	return mw.TokenGenerator(ctx, data)
}

// buildClaims 构建 JWT claims
func (mw *GinJWTMiddleware) buildClaims(data any, now time.Time) jwt.MapClaims {
	claims := jwt.MapClaims{}

	// 添加 PayloadFunc 提供的 claims
	if mw.PayloadFunc != nil {
		for k, v := range mw.PayloadFunc(data) {
			// 框架控制的 claim 不可覆盖
			if k != "exp" && k != "orig_iat" {
				claims[k] = v
			}
		}
	}

	// 设置标准 claim
	claims[mw.ExpField] = now.Add(mw.getAccessTokenTimeout(data)).Unix()
	claims["iat"] = now.Unix()
	claims["orig_iat"] = now.Unix()

	return claims
}

// generateAccessToken 生成 JWT 访问令牌
func (mw *GinJWTMiddleware) generateAccessToken(claims jwt.MapClaims) (string, error) {
	var token *jwt.Token

	if mw.KeyFunc != nil {
		// 使用动态 KeyFunc
		token = jwt.NewWithClaims(jwt.GetSigningMethod(mw.SigningAlgorithm), claims)
		token.Method = jwt.GetSigningMethod(mw.SigningAlgorithm)
	} else {
		switch mw.SigningAlgorithm {
		case "HS256", "HS384", "HS512":
			// 对称算法
			token = jwt.NewWithClaims(jwt.GetSigningMethod(mw.SigningAlgorithm), claims)
		case "RS256", "RS384", "RS512":
			// RSA 算法
			token = jwt.NewWithClaims(jwt.GetSigningMethod(mw.SigningAlgorithm), claims)
			token.Header["kid"] = "rsa-key-1"
		default:
			return "", fmt.Errorf("unsupported signing algorithm: %s", mw.SigningAlgorithm)
		}
	}

	// 签名
	var signingKey any
	if mw.KeyFunc != nil {
		// KeyFunc 在解析时使用
		signingKey = mw.Key
	} else {
		switch mw.SigningAlgorithm {
		case "HS256", "HS384", "HS512":
			signingKey = mw.Key
		case "RS256", "RS384", "RS512":
			signingKey = mw.privKey
		}
	}

	return token.SignedString(signingKey)
}

// generateRefreshToken 生成随机刷新令牌
func (mw *GinJWTMiddleware) generateRefreshToken() (string, error) {
	bytes := make([]byte, mw.RefreshTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// getAccessTokenTimeout 获取访问令牌超时时间
func (mw *GinJWTMiddleware) getAccessTokenTimeout(data any) time.Duration {
	if mw.TimeoutFunc != nil {
		return mw.TimeoutFunc(data)
	}
	return mw.Timeout
}

// getRefreshTokenTimeout 获取刷新令牌超时时间
func (mw *GinJWTMiddleware) getRefreshTokenTimeout() time.Duration {
	if mw.MaxRefresh > 0 {
		if mw.RefreshTokenTimeout > mw.MaxRefresh {
			return mw.MaxRefresh
		}
	}
	return mw.RefreshTokenTimeout
}

// ParseTokenString 解析 JWT 字符串
func (mw *GinJWTMiddleware) ParseTokenString(token string) (*jwt.Token, error) {
	// 解析令牌
	parsedToken, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(token *jwt.Token) (any, error) {
		// 验证算法
		if token.Method == nil {
			return nil, errors.New("token method is nil")
		}
		// jwt v5 使用 method.Alg() 获取算法名称
		if token.Method.Alg() != mw.SigningAlgorithm {
			return nil, fmt.Errorf("invalid signing algorithm: expected %s, got %s", mw.SigningAlgorithm, token.Method.Alg())
		}

		// 返回密钥
		if mw.KeyFunc != nil {
			return mw.KeyFunc(token)
		}

		switch mw.SigningAlgorithm {
		case "HS256", "HS384", "HS512":
			return mw.Key, nil
		case "RS256", "RS384", "RS512":
			return mw.pubKey, nil
		default:
			return nil, fmt.Errorf("unsupported signing algorithm: %s", mw.SigningAlgorithm)
		}
	}, mw.parseOptions()...)

	if err != nil {
		return nil, err
	}

	return parsedToken, nil
}

// parseOptions 返回 JWT 解析选项
func (mw *GinJWTMiddleware) parseOptions() []jwt.ParserOption {
	if mw.ParseOptions != nil {
		return mw.ParseOptions
	}
	return []jwt.ParserOption{}
}

// ClearSensitiveData 清除内存中的敏感数据
func (mw *GinJWTMiddleware) ClearSensitiveData() {
	// 清零密钥
	for i := range mw.Key {
		mw.Key[i] = 0
	}
	for i := range mw.PrivKeyBytes {
		mw.PrivKeyBytes[i] = 0
	}
	for i := range mw.PubKeyBytes {
		mw.PubKeyBytes[i] = 0
	}

	// 清空内存存储
	if mw.inMemoryStore != nil {
		mw.inMemoryStore.Cleanup()
	}
}
