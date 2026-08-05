package http

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

type (
	// JWTInfo contains the information about JWT
	JWTInfo struct {
		ApplicationID string   // Application ID from the JWT token
		Audience      []string // Audience intended by the token
		DeviceID      string   // The device id where the token came from
		Domain        string   // The application domain that the token is intended for
		Raw           string   // Raw JWT token
		TenantID      string   // Tenant ID from the JWT token
		UserName      string   // User account authenticated and produced the token
		Verification  string   // Verification value for application to API. This is encrypted by its own secret
		Valid         bool     // Indicates that the request has a valid JWT token
	}
)

// ParseJwt validates, parses JWT and returns information using HMAC256 algorithm
func ParseJwt(token, secretKey string, validateTimes bool) (*JWTInfo, error) {
	sk, err := sanitizeSecretKey(secretKey)
	if err != nil {
		return nil, err
	}

	// Parse JWT
	HMAC := jwt.NewHS256([]byte(sk))

	var (
		pl CustomPayload
	)

	// Validate claims "iat", "exp" and "aud".
	if validateTimes {
		now := time.Now()
		// Use jwt.ValidatePayload to build a jwt.VerifyOption.
		// Validators are run in the order informed.
		validator := jwt.ValidatePayload(
			&pl.Payload,
			jwt.IssuedAtValidator(now),
			jwt.ExpirationTimeValidator(now),
			jwt.NotBeforeValidator(now))
		_, err = jwt.Verify([]byte(token), HMAC, &pl, validator)
	} else {
		_, err = jwt.Verify([]byte(token), HMAC, &pl)
	}
	if err != nil {
		return nil, err
	}
	return &JWTInfo{
		Audience:      pl.Audience,
		UserName:      pl.UserName,
		Domain:        pl.Domain,
		DeviceID:      pl.DeviceID,
		ApplicationID: pl.ApplicationID,
		TenantID:      pl.TenantID,
		Verification:  pl.Verification,
		Raw:           token,
		Valid:         true,
	}, nil
}

// ParseJwtPayload validates, parses JWT and returns CustomPayload information using HMAC256 algorithm
func ParseJwtPayload(token, secretKey string, validateTimes bool) (*CustomPayload, error) {
	sk, err := sanitizeSecretKey(secretKey)
	if err != nil {
		return nil, err
	}

	// Parse JWT
	HMAC := jwt.NewHS256([]byte(sk))

	var (
		pl CustomPayload
	)

	// Validate claims "iat", "exp" and "aud".
	if validateTimes {
		now := time.Now()
		// Use jwt.ValidatePayload to build a jwt.VerifyOption.
		// Validators are run in the order informed.
		validator := jwt.ValidatePayload(
			&pl.Payload,
			jwt.IssuedAtValidator(now),
			jwt.ExpirationTimeValidator(now),
			jwt.NotBeforeValidator(now))
		_, err = jwt.Verify([]byte(token), HMAC, &pl, validator)
	} else {
		_, err = jwt.Verify([]byte(token), HMAC, &pl)
	}
	if err != nil {
		return nil, err
	}
	return &CustomPayload{
		Payload:       pl.Payload,
		UserName:      pl.UserName,
		Domain:        pl.Domain,
		ApplicationID: pl.ApplicationID,
		DeviceID:      pl.DeviceID,
		TenantID:      pl.TenantID,
		Verification:  pl.Verification,
	}, nil
}

// SignJwt builds a JWT token using HMAC256 algorithm
func SignJwt(claims *map[string]any, secretKey string) string {
	pl := BuildJwtPayload(claims)
	if pl == nil {
		return ""
	}
	sk, err := sanitizeSecretKey(secretKey)
	if err != nil {
		return ""
	}

	token, err := jwt.Sign(*pl, jwt.NewHS256([]byte(sk)))
	if err != nil {
		return ""
	}
	return string(token)
}

// SignJwtWithPayload builds a JWT token with custom payload using HMAC256 algorithm
func SignJwtWithPayload(pl *CustomPayload, secretKey string) string {
	if pl == nil {
		return ""
	}
	sk, err := sanitizeSecretKey(secretKey)
	if err != nil {
		return ""
	}

	token, err := jwt.Sign(*pl, jwt.NewHS256([]byte(sk)))
	if err != nil {
		return ""
	}
	return string(token)
}

// BuildJwtClaims builds JWT claim from CustomPayload
func BuildJwtClaims(pl *CustomPayload) *map[string]any {
	claims := make(map[string]any)
	if pl.Issuer != "" {
		claims["iss"] = pl.Issuer
	}
	if pl.Subject != "" {
		claims["sub"] = pl.Subject
	}
	if len(pl.Audience) > 0 {
		claims["aud"] = pl.Audience
	}
	if pl.ExpirationTime != nil {
		claims["exp"] = pl.ExpirationTime.Unix()
	}
	if pl.NotBefore != nil {
		claims["nbf"] = pl.NotBefore.Unix()
	}
	if pl.IssuedAt != nil {
		claims["iat"] = pl.IssuedAt.Unix()
	}
	if pl.UserName != "" {
		claims["usr"] = pl.UserName
	}
	if pl.Domain != "" {
		claims["dom"] = pl.Domain
	}
	if pl.ApplicationID != "" {
		claims["app"] = pl.ApplicationID
	}
	if pl.DeviceID != "" {
		claims["dev"] = pl.DeviceID
	}
	if pl.JWTID != "" {
		claims["jti"] = pl.JWTID
	}
	if pl.TenantID != "" {
		claims["tnt"] = pl.TenantID
	}
	if pl.Verification != "" {
		claims["vfy"] = pl.Verification
	}
	return &claims
}

// BuildJwtPayload builds custom payload from claims
func BuildJwtPayload(claims *map[string]any) *CustomPayload {
	if claims == nil {
		return nil
	}
	clm := *claims

	var (
		usr, dom, app, dev      string
		iss, sub, jti, tnt, vfy string
		exp, nbf, iat           int64
		aud                     jwt.Audience
	)

	if v, ok := clm["iss"]; ok {
		iss, _ = asString(v)
	}
	if v, ok := clm["sub"]; ok {
		sub, _ = asString(v)
	}
	if v, ok := clm["aud"]; ok {
		if sl, ok := asStringSlice(v); ok {
			aud = jwt.Audience(sl)
		}
	}
	if v, ok := clm["exp"]; ok {
		exp, _ = asInt64(v)
	}
	if v, ok := clm["nbf"]; ok {
		nbf, _ = asInt64(v)
	}
	if v, ok := clm["iat"]; ok {
		iat, _ = asInt64(v)
	}
	if v, ok := clm["usr"]; ok {
		usr, _ = asString(v)
	}
	if v, ok := clm["dom"]; ok {
		dom, _ = asString(v)
	}
	if v, ok := clm["app"]; ok {
		app, _ = asString(v)
	}
	if v, ok := clm["dev"]; ok {
		dev, _ = asString(v)
	}
	if v, ok := clm["jti"]; ok {
		jti, _ = asString(v)
	}
	if v, ok := clm["tnt"]; ok {
		tnt, _ = asString(v)
	}
	if v, ok := clm["vfy"]; ok {
		vfy, _ = asString(v)
	}

	unixt := func(unixts int64) *jwt.Time {
		if unixts <= 0 {
			return nil
		}
		return &jwt.Time{Time: time.Unix(unixts, 0).UTC()}
	}

	return &CustomPayload{
		Payload: jwt.Payload{
			Issuer:         iss,
			Subject:        sub,
			Audience:       aud,
			ExpirationTime: unixt(exp),
			NotBefore:      unixt(nbf),
			IssuedAt:       unixt(iat),
			JWTID:          jti,
		},
		UserName:      usr,
		Domain:        dom,
		ApplicationID: app,
		DeviceID:      dev,
		TenantID:      tnt,
		Verification:  vfy,
	}
}

// ValidateJwt validates JWT and returns information using HMAC256 algorithm
func ValidateJwt(r *http.Request, secretKey string, validateTimes bool) (*JWTInfo, error) {
	var (
		jwtfromck,
		jwth string
		jwtp []string
	)
	// Get Authorization header
	if jwth = r.Header.Get("Authorization"); len(jwth) == 0 {
		return nil, ErrAuthorizationHeaderNotSet
	}
	if jwtp = strings.Split(jwth, " "); len(jwtp) < 2 {
		return nil, ErrInvalidAuthorizationHeader
	}
	if !strings.EqualFold(strings.TrimSpace(jwtp[0]), "bearer") {
		return nil, ErrInvalidAuthorizationBearer
	}
	if jwtfromck = strings.TrimSpace(jwtp[1]); len(jwtfromck) == 0 {
		return nil, ErrInvalidAuthorizationToken
	}
	return ParseJwt(jwtfromck, secretKey, validateTimes)
}

// ValidateJwtPayload validates JWT and returns custom payload information using HMAC256 algorithm
func ValidateJwtPayload(r *http.Request, secretKey string, validateTimes bool) (*CustomPayload, error) {
	var (
		jwtfromck,
		jwth string
		jwtp []string
	)
	// Get Authorization header
	if jwth = r.Header.Get("Authorization"); len(jwth) == 0 {
		return nil, ErrAuthorizationHeaderNotSet
	}
	if jwtp = strings.Split(jwth, " "); len(jwtp) < 2 {
		return nil, ErrInvalidAuthorizationHeader
	}
	if !strings.EqualFold(strings.TrimSpace(jwtp[0]), "bearer") {
		return nil, ErrInvalidAuthorizationBearer
	}
	if jwtfromck = strings.TrimSpace(jwtp[1]); len(jwtfromck) == 0 {
		return nil, ErrInvalidAuthorizationToken
	}
	return ParseJwtPayload(jwtfromck, secretKey, validateTimes)
}

// EncodeVerification encrypts and encodes the plain verification code using the secret key.
func EncodeVerification(plainVfy string, secretKey string) (string, error) {
	sk, err := sanitizeSecretKey(secretKey)
	if err != nil {
		return "", err
	}
	vfb, err := encrypt([]byte(plainVfy), []byte(sk))
	if err != nil {
		return "", err
	}
	vfbs := base64.RawStdEncoding.EncodeToString(vfb)
	return vfbs, nil
}

// DecodeVerification decryptes and decodes the encoded verification code using the secret key
func DecodeVerification(encVfy string, secretKey string) (string, error) {
	sk, err := sanitizeSecretKey(secretKey)
	if err != nil {
		return "", err
	}
	vfb, err := base64.RawStdEncoding.DecodeString(encVfy)
	if err != nil {
		return "", err
	}

	vfbs, err := decrypt(vfb, []byte(sk))
	if err != nil {
		return "", err
	}

	return string(vfbs), nil
}

func sanitizeSecretKey(sk string) (string, error) {
	skl := len(sk)
	if skl == 0 {
		return "", ErrSecretKeyNotSet
	}
	if skl < 32 {
		sk += strings.Repeat("1", 32-skl)
	}
	return sk, nil
}

func encrypt(plainText []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plainText, nil), nil
}

func decrypt(cipherText []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, payload := cipherText[:nonceSize], cipherText[nonceSize:]
	return gcm.Open(nil, nonce, payload, nil)
}
