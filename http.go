package http

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	br "github.com/andybalholm/brotli"
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stdutil/log"
	nv "github.com/stdutil/name-value"
	rslt "github.com/stdutil/result"
)

const (
	REQUEST_VERSION  string = "1.1.0.0"
	REQUEST_MODIFIED string = "24052025"
)

var (
	rto     int // Request timeout in seconds
	ct      *http.Transport
	logFunc func(string, ...any)
)

var (
	ErrRequestHasNoPayload        = errors.New("the request has no payload")
	ErrInvalidAccessToken         = errors.New("invalid access token")
	ErrAuthorizationHeaderNotSet  = errors.New("authorization header not set")
	ErrInvalidAuthorizationHeader = errors.New("invalid authorization header")
	ErrInvalidAuthorizationBearer = errors.New("invalid authorization bearer")
	ErrInvalidAuthorizationToken  = errors.New("invalid authorization token")
	ErrSecretKeyNotSet            = errors.New("secret key not set")
)

type (
	// CustomPayload - payload for JWT
	CustomPayload struct {
		jwt.Payload
		UserName      string `json:"usr,omitempty"` // Username payload for JWT
		Domain        string `json:"dom,omitempty"` // Domain payload for JWT
		ApplicationID string `json:"app,omitempty"` // Application payload for JWT
		DeviceID      string `json:"dev,omitempty"` // Device id payload for JWT
		TenantID      string `json:"tnt,omitempty"` // Tenant id payload for JWT
	}
	// ResultData - a result structure and a JSON raw message
	ResultData struct {
		rslt.Result
		Data json.RawMessage `json:"data"`
	}
)

func init() {
	rto = 30
	ct = http.DefaultTransport.(*http.Transport).Clone()
	ct.MaxIdleConns = 100
	ct.MaxConnsPerHost = 100
	ct.MaxIdleConnsPerHost = 100
	logFunc = func(s string, a ...any) {} // set to black hole function
}

// ExecuteApi (ChatGPT optimized) wraps http operation that change or read data and returns a byte array.
//
// On headers:
//   - Content-Type: If this header is not set, it defaults to "application/json"
//   - Content-Encoding: If compressed is true, it is set to "gzip"
func ExecuteApi[T any](method, endPoint string, payload []byte, opts ...RequestOption) (T, error) {
	var x T

	// Apply options
	rp := RequestParam{}
	for _, o := range opts {
		if o != nil {
			o(&rp)
		}
	}

	// Overrides the default log function
	// or previously set function
	lf := logFunc
	if rp.LogFunc != nil {
		lf = rp.LogFunc
	}

	// Create request
	req, err := http.NewRequest(method, endPoint, bytes.NewBuffer(payload))
	if err != nil {
		lf("%s: %s %s - %s", string(log.Error), method, endPoint, err)
		return x, err
	}

	// Default headers
	req.Header.Set("User-Agent", fmt.Sprintf("com.github.stdutil.http/%s-%s", REQUEST_VERSION, REQUEST_MODIFIED))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept", "*/*")
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		req.Header.Set("Idempotency-Key", uuid.New().String())
	}

	// Get etag from the container list and send an If-None-Match
	if method == http.MethodGet || method == http.MethodHead {
		if etag, ok := ShouldSendIfNoneMatch(endPoint); ok {
			req.Header.Set("If-None-Match", etag)
		}
	}

	for k, v := range rp.Headers {
		if k == "" || v == "" {
			continue
		}
		if strings.EqualFold(k, "cookie") {
			for pair := range strings.SplitSeq(v, ";") {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}
				name, val, ok := strings.Cut(pair, "=")
				if !ok {
					continue
				}
				req.AddCookie(&http.Cookie{
					Name:  strings.TrimSpace(name),
					Value: strings.TrimSpace(val),
				})
			}
		} else {
			req.Header.Set(k, v)
		}
	}

	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Compression headers
	if rp.Compressed {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
			req.Header.Set("Content-Encoding", "gzip")
		}
	}

	to := rp.TimeOut
	if to <= 0 {
		to = rto // default from init() or SetRequestTimeout
	}

	// HTTP client
	client := http.Client{
		Timeout:   time.Second * time.Duration(to),
		Transport: ct,
	}
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("%s: Requesting resource at %s", err, endPoint)
		lf("%s: %s %s - %s", string(log.Error), method, endPoint, err)
		return x, err
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		err = fmt.Errorf("HTTP error: %d %s (Requesting resource at %s)",
			resp.StatusCode,
			http.StatusText(resp.StatusCode),
			endPoint,
		)
		lf("%s: %s %s - %s", string(log.Error), method, endPoint, err)
		return x, err
	}

	// Store ETag for later retrieval
	if method == http.MethodGet || method == http.MethodHead {
		if etag := resp.Header.Get("ETag"); etag != "" {
			SetETag(endPoint, etag)
		}
	}

	// Decode response body
	var body []byte
	ce := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if resp.Uncompressed || ce == "" {
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			if !(errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
				lf("%s: %s %s - %s", string(log.Error), method, endPoint, err)
				return x, fmt.Errorf("read failed: %w", err)
			}
		}
	} else {
		if ce == "gzip" {
			x, err = func() (T, error) {
				gzr, err := gzip.NewReader(resp.Body)
				if err != nil {
					return x, fmt.Errorf("read failed: %w", err)
				}
				defer gzr.Close()

				body, err = io.ReadAll(gzr) // single growing buffer
				if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
					return x, fmt.Errorf("read failed: %w", err)
				}
				return x, nil
			}()
			if err != nil {
				lf("%s: %s %s - %s", string(log.Error), method, endPoint, err)
				return x, err
			}
		}
		if ce == "br" {
			gzr := br.NewReader(resp.Body)
			body, err = io.ReadAll(gzr)
			if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
				lf("%s: %s %s - %s", string(log.Error), method, endPoint, err)
				return x, fmt.Errorf("read failed: %w", err)
			}
		}
	}

	// Type-specific return
	switch any(x).(type) {
	case []byte:
		return any(body).(T), nil
	default:
		// Get the response content type
		// Change content type if assumed content type is set
		// If ct is empty, fallback to request content type
		ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
		if act := strings.ToLower(strings.TrimSpace(rp.AssumedContentType)); act != "" {
			ct = act
		}
		if ct == "" {
			ct = strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
		}
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			ct = ct[:i]
		}

		// Default content-type (default)
		switch ct {
		case "application/json":
			err = json.Unmarshal(body, &x)
			if err != nil {
				lf("%s: %s %s - %s", string(log.Error), method, endPoint, err)
			}
			return x, err
		case "text/xml", "application/xml":
			err = xml.Unmarshal(body, &x)
			if err != nil {
				lf("%s: %s %s - %s", string(log.Error), method, endPoint, err)
			}
			return x, err
		case "text/plain":
			if v, ok := any(string(body)).(T); ok {
				return v, nil
			}
			return x, err
		}

		// Unknown content type, best-effort fallback:
		if v, ok := any(body).(T); ok { // T == []byte but we already handled that; still safe
			return v, nil
		}
		return x, nil
	}
}

// ExecuteJsonApi wraps http operation that change or read data and returns a custom result
func ExecuteJsonApi(method string, endPoint string, payload []byte, opts ...RequestOption) (rd ResultData) {
	rd = ResultData{
		Result: rslt.InitResult(),
	}
	trd, err := ExecuteApi[ResultData](method, endPoint, payload, opts...)
	if err != nil {
		rd.Result.AddErr(err)
		return
	}

	// Assign temp to result
	rd.Data = trd.Data
	rd.FocusControl = trd.FocusControl
	rd.Operation = trd.Operation
	rd.Page = trd.Page
	rd.PageCount = trd.PageCount
	rd.PageSize = trd.PageSize
	rd.Tag = trd.Tag
	rd.TaskID = trd.TaskID
	rd.WorkerID = trd.WorkerID
	rd.Return(rslt.Status(trd.Status))
	for _, m := range trd.Messages {
		if m == "" {
			continue
		}
		msgType := m[0:3]
		msg := m[3:]
		if strings.HasPrefix(msg, ":") {
			msg = msg[2:]
		}
		if strings.HasPrefix(msg, "[") {
			if endBr := strings.Index(msg, "]"); endBr != -1 {
				rd.Prefix = msg[1:endBr]
				msg = msg[endBr+3:]
			}
		}
		switch msgType {
		case string(log.Warn):
			rd.Result.AddWarning("%s", msg)
		case string(log.Error):
			rd.Result.AddError("%s", msg)
		case string(log.Fatal):
			rd.Result.AddError("%s", msg)
		case string(log.Success):
			rd.Result.AddSuccess("%s", msg)
		case string(log.App):
			rd.Result.AddRawMsg("%s", msg)
		}
	}

	return
}

// GetBody retrieves the request body
func GetBody(r *http.Request) []byte {
	return getBody(r, nil)
}

// GetRequestVarsOnly get request variables
func GetRequestVarsOnly(r *http.Request, preserveCmdCase bool) RequestVars {
	rv := RequestVars{
		Method: strings.ToUpper(r.Method),
	}
	rv.Body = getBody(r, &rv.Variables.IsMultipart)
	rv.HasBody = len(rv.Body) > 0

	// Query Strings
	rv.Variables.QueryString = ParseQueryString(&r.URL.RawQuery)
	rv.Variables.HasQueryString = len(rv.Variables.QueryString.Pair) > 0
	if rv.Variables.IsMultipart {
		r.ParseMultipartForm(30 << 20)
	} else {
		r.ParseForm()
	}
	// Get Form data
	rv.Variables.FormData = nv.NameValues{
		Pair: make(map[string]any),
	}
	for k, v := range r.PostForm {
		rv.Variables.FormData.Pair[k] = strings.Join(v[:], ",")
	}
	rv.Variables.HasFormData = len(rv.Variables.FormData.Pair) > 0
	// Get route commands
	rv.Variables.Command, rv.Variables.Key = ParseRouteVars(r, preserveCmdCase)
	return rv
}

// GetRequestVars requests variables and return JWT validation result
func GetRequestVars(r *http.Request, secretKey string, validateTimes, preserveCmdCase bool) (RequestVars, error) {
	rv := GetRequestVarsOnly(r, preserveCmdCase)
	rv.Token = nil
	// Silently ignore OPTIONS methid
	if strings.EqualFold(r.Method, http.MethodOptions) {
		return rv, nil
	}
	ji, err := ValidateJwt(r, secretKey, validateTimes)
	if err != nil {
		return rv, err
	}
	rv.Token = ji
	return rv, nil
}

// GetRouteVar retrieves the variable in the route to the desired type T.
func GetRouteVar[T KeyTypes](r *http.Request, name string) T {
	var zero T
	s := chi.URLParam(r, name)
	switch any(*new(T)).(type) {
	case string:
		return any(s).(T)
	case int:
		if len(s) == 0 {
			return zero
		}
		v, _ := strconv.Atoi(s)
		return any(v).(T)
	case int64:
		if len(s) == 0 {
			return zero
		}
		v, _ := strconv.ParseInt(s, 10, 64)
		return any(v).(T)
	}
	return zero
}

// IsJsonGood checks if the request has body and attempts to marshal to Json
func IsJsonGood(r *http.Request, v any) error {
	b := getBody(r, nil)
	if len(b) == 0 {
		return ErrRequestHasNoPayload
	}
	if err := json.Unmarshal(b, v); err != nil {
		return err
	}
	return nil
}

// ParseQueryString parses the query string into a column value
func ParseQueryString(qs *string) nv.NameValues {
	ret := nv.NameValues{
		Pair: make(map[string]any),
	}
	rv, _ := url.ParseQuery(*qs)
	for k, v := range rv {
		ret.Pair[k] = strings.Join(v[:], ",")
	}
	return ret
}

// ParsePath parses a url path and returns an array of path
//
//   - normalizePathCase is an option to make all path lower case for ease of comparison. Defaults to true.
//   - inclSlashPfx is an option to include slash prefix in the results, Defaults to false.
func ParsePath(urlPath string, normalizePathCase, inclSlashPfx bool) ([]string, string) {

	var (
		ptn, id,
		slashPfx string
		hasTrlngSlsh bool
	)
	paths := make([]string, 0, 7)

	if urlPath == "" {
		return paths, id
	}

	urlPath = strings.ReplaceAll(urlPath, `\`, `/`)
	if urlPath == "/" {
		paths = append(paths, "/")
		return paths, id
	}

	ptn = urlPath
	if ptn != "" {
		hasTrlngSlsh = ptn[len(ptn)-1:] == `/`
	}

	if inclSlashPfx {
		slashPfx = "/"
	}

	rawPath := strings.FieldsFunc(
		ptn,
		func(c rune) bool {
			return c == '/'
		})
	pathlen := len(rawPath)
	if pathlen == 0 {
		return paths, id
	}

	// If path length is 1, we might have a key.
	// But if the path is not a number, it might be a command
	if pathlen == 1 {
		if pth := rawPath[0]; len(pth) > 0 {
			if hasTrlngSlsh {
				if normalizePathCase {
					pth = strings.ToLower(pth)
				}
				paths = append(paths, slashPfx+pth)
			} else {
				id = pth
			}
		}
		return paths, id
	}

	// If path length is greater than 1, we transfer all paths
	// to the cmd array except the last one. The last one will
	// be checked if it has a trailing slash
	if pathlen > 1 {
		for i, ck := range rawPath {
			if i < pathlen-1 && len(ck) > 0 {
				if normalizePathCase {
					ck = strings.ToLower(ck)
				}
				paths = append(paths, slashPfx+ck)
			}
		}
		if pth := rawPath[pathlen-1]; len(pth) > 0 {
			if hasTrlngSlsh {
				if normalizePathCase {
					pth = strings.ToLower(pth)
				}
				paths = append(paths, slashPfx+pth)
			} else {
				id = pth
			}
		}
	}
	return paths, id
}

// ParseJwt validates, parses JWT and returns information using HMAC256 algorithm
func ParseJwt(token, secretKey string, validateTimes bool) (*JWTInfo, error) {
	sk := secretKey
	skl := len(sk)
	if skl == 0 {
		return nil, ErrSecretKeyNotSet
	}
	var (
		pl  CustomPayload
		err error
	)

	if skl < 32 {
		sk += strings.Repeat("1", 32-skl)
	}

	// Parse JWT
	HMAC := jwt.NewHS256([]byte(sk))

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
		Raw:           token,
		Valid:         true,
	}, nil
}

// ParseJwtPayload validates, parses JWT and returns CustomPayload information using HMAC256 algorithm
func ParseJwtPayload(token, secretKey string, validateTimes bool) (*CustomPayload, error) {
	sk := secretKey
	skl := len(sk)
	if skl == 0 {
		return nil, ErrSecretKeyNotSet
	}
	if skl < 32 {
		sk += strings.Repeat("1", 32-skl)
	}

	// Parse JWT
	HMAC := jwt.NewHS256([]byte(sk))

	var (
		pl  CustomPayload
		err error
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
	}, nil
}

// ParseRouteVars parses custom routes from a route handler
func ParseRouteVars(r *http.Request, preserveCmdCase bool) ([]string, string) {
	up := r.URL.Path

	// Sanitize the pattern built by chi.
	// A path should be distinguished apart from the id or key
	pt := strings.TrimSuffix(chi.RouteContext(r.Context()).RoutePattern(), "*")
	if strings.HasSuffix(up, "/") && !strings.HasSuffix(pt, "/") {
		pt += "/"
	}

	// Trim the url by URL path.
	// The remaining text will be the path to evaluate
	ptn := strings.Replace(r.URL.Path, pt, "", -1)

	// ParsePath expects paths enclosed in forward slashes.
	// This requirement allows ParsePath to identify which is
	// a path and an id (key).
	return ParsePath(ptn, !preserveCmdCase, false)
}

// SetLog sets a log function to ExecuteAPI calls
func SetLog(f func(string, ...any)) {
	if f == nil {
		f = func(string, ...any) {}
	}
	logFunc = f // assume called once at startup, before goroutines
}

// SetRequestTimeOut sets the new timeout value
func SetRequestTimeout(timeOut int) {
	rto = timeOut
}

// SignJwt builds a JWT token using HMAC256 algorithm
func SignJwt(claims *map[string]any, secretKey string) string {
	pl := BuildJwtPayload(claims)
	if pl == nil {
		return ""
	}
	sk := secretKey
	skl := len(sk)
	if skl == 0 {
		return ""
	}
	if skl < 32 {
		sk += strings.Repeat("1", 32-skl)
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
	sk := secretKey
	skl := len(sk)
	if skl == 0 {
		return ""
	}
	if skl < 32 {
		sk += strings.Repeat("1", 32-skl)
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
	return &claims
}

// BuildJwtPayload builds custom payload from claims
func BuildJwtPayload(claims *map[string]any) *CustomPayload {
	if claims == nil {
		return nil
	}
	clm := *claims

	var (
		usr, dom, app, dev string
		iss, sub, jti, tnt string
		exp, nbf, iat      int64
		aud                jwt.Audience
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

func getBody(r *http.Request, isMultiPart *bool) []byte {
	var c1 string
	const (
		mulpart string = "multipart/form-data"
		furlenc string = "application/x-www-form-urlencoded"
	)
	if cType := strings.Split(r.Header.Get("Content-Type"), ";"); len(cType) > 0 {
		c1 = strings.ToLower(strings.TrimSpace(cType[0]))
	}
	method := strings.ToUpper(r.Method)
	if isMultiPart == nil {
		isMultiPart = new(bool)
	}
	*isMultiPart = c1 == mulpart
	useBody := (c1 != furlenc && !*isMultiPart) && (method == "POST" || method == "PUT" || method == "DELETE")
	if !useBody || r.Body == nil {
		return nil
	}

	// single read, no closure, no extra empty slice
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return body
}

func getJsonConverted[T any](result *ResultData) rslt.ResultAny[T] {
	var data T
	if len(result.Data) == 0 {
		return rslt.ResultAny[T]{
			Result: result.Result,
			Data:   data,
		}
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return rslt.ResultAny[T]{
			Result: rslt.InitResult(
				rslt.WithStatus(rslt.EXCEPTION),
				rslt.WithMessage(err.Error()),
			),
			Data: data,
		}
	}
	return rslt.ResultAny[T]{
		Result: result.Result,
		Data:   data,
	}
}

// asString tries to coerce common types into string.
func asString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case fmt.Stringer:
		return t.String(), true
	case []byte:
		return string(t), true
	default:
		return "", false
	}
}

// asInt64 supports int, int64, float64, json.Number, and numeric strings.
func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int8:
		return int64(t), true
	case int16:
		return int64(t), true
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case uint:
		return int64(t), true
	case uint8:
		return int64(t), true
	case uint16:
		return int64(t), true
	case uint32:
		return int64(t), true
	case uint64:
		if t > ^uint64(0)>>1 {
			return 0, false // overflow if we try to cast
		}
		return int64(t), true
	case float32:
		return int64(t), true
	case float64:
		return int64(t), true
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return 0, false
		}
		return n, true
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// asStringSlice handles string, []string, and []any of strings.
func asStringSlice(v any) ([]string, bool) {
	switch t := v.(type) {
	case []string:
		return t, true
	case string:
		return []string{t}, true
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := asString(e)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

// func safeMapWrite[T any](ptrMap *map[string]T, key string, value T, rw *sync.RWMutex) bool {
// 	defer func() {
// 		recover()
// 	}()
// 	// Prepare mutex
// 	// attempt writing to map
// 	if rw.TryLock() {
// 		defer rw.Unlock()
// 		(*ptrMap)[key] = value
// 	}
// 	return true
// }
