package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
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
	REQUEST_VERSION  string = "1.2.0.0"
	REQUEST_MODIFIED string = "03072026"
)

var (
	rto     int // Request timeout in seconds
	ct      *http.Transport
	logFunc func(string, ...any)
	rs      ResponseStorage
)

var (
	ErrRequestHasNoPayload        = errors.New("http error: the request has no payload")
	ErrInvalidAccessToken         = errors.New("http error: invalid access token")
	ErrAuthorizationHeaderNotSet  = errors.New("http error: authorization header not set")
	ErrInvalidAuthorizationHeader = errors.New("http error: invalid authorization header")
	ErrInvalidAuthorizationBearer = errors.New("http error: invalid authorization bearer")
	ErrInvalidAuthorizationToken  = errors.New("http error: invalid authorization token")
	ErrSecretKeyNotSet            = errors.New("http error: secret key not set")
	ErrStatusCodeNotModified      = errors.New("http error: status code not modified")
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

// ExecuteApi wraps http operation that change or read data and returns a byte array.
//
// On headers:
//   - Content-Type: If this header is not set, it defaults to "application/json"
//   - Content-Encoding: If compressed is true, it is set to "gzip"
func ExecuteApi[T any](method, endpoint string, payload []byte, opts ...RequestOption) (T, error) {
	var x T

	// Apply options
	rp := RequestParam{
		TimeOut:            rto,
		Compressed:         false,
		Headers:            make(map[string]string),
		LogFunc:            nil,
		AssumedContentType: "application/json",
		ReturnBodyOn304:    false,
	}
	for _, o := range opts {
		if o != nil {
			o(&rp)
		}
	}

	// Overrides the default log function or previously set function
	lf := logFunc
	if rp.LogFunc != nil {
		lf = rp.LogFunc
	}

	to := rto // default from init() or SetRequestTimeout
	if rp.TimeOut > 0 {
		to = rp.TimeOut
	}

	pl := payload
	if rp.Compressed && (method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) {
		var err error
		pl, err = compressGzip(payload)
		if err != nil {
			lf("%v: %s %s - %s", log.Error, method, endpoint, err)
			return x, err
		}
	}

	// Create request
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(pl))
	if err != nil {
		lf("%v: %s %s - %s", log.Error, method, endpoint, err)
		return x, err
	}

	// Default headers
	req.Header.Set("User-Agent", fmt.Sprintf("com.github.stdutil.http/%s-%s", REQUEST_VERSION, REQUEST_MODIFIED))
	req.Header.Set("Accept", "*/*")

	// Set Idempotency-Key header for POST/PUT/PATCH requests
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		req.Header.Set("Idempotency-Key", uuid.New().String())
	}

	canOrShouldStore := rs != nil && method == http.MethodGet

	// Get ETag from the container list and send an If-None-Match if the response store is available
	if canOrShouldStore {
		if meta, ok := rs.Get(endpoint); ok {
			req.Header.Set("If-None-Match", meta.ETag)
		}
	}

	// Override headers from request options
	for k, v := range rp.Headers {
		if k == "" || v == "" {
			continue
		}
		if !strings.EqualFold(k, "cookie") {
			req.Header.Set(k, v)
			continue
		}
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

	// HTTP client
	client := http.Client{
		Timeout:   time.Second * time.Duration(to),
		Transport: ct,
	}

	resp, err := client.Do(req)
	if err != nil {
		lf("%v: %s %s - %s", log.Error, method, endpoint, err)
		return x, err
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode == http.StatusNotModified {
		if !canOrShouldStore || !rp.ReturnBodyOn304 {
			return x, ErrStatusCodeNotModified
		}
	} else if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		err = fmt.Errorf("http error: %d %s",
			resp.StatusCode,
			http.StatusText(resp.StatusCode),
		)
		lf("%v: %s %s - %s", log.Error, method, endpoint, err)
		return x, err
	}

	// Determine content type
	ct := determineContentType(resp, req, &rp)

	if method == http.MethodHead {
		return x, nil
	}

	// Return body
	var body []byte
	if resp.StatusCode == http.StatusNotModified {
		meta, ok := rs.Get(endpoint)
		if !ok {
			return x, ErrStatusCodeNotModified
		}
		body = meta.Body
		ct = meta.ContentType
	} else {
		ce := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
		if !resp.Uncompressed && ce != "" {
			switch ce {
			case "gzip":
				body, err = readGzip(resp)
				if err != nil {
					lf("%v: %s %s - %s", log.Error, method, endpoint, err)
					return x, err
				}
			case "br":
				body, err = readBrotli(resp)
				if err != nil {
					lf("%v: %s %s - %s", log.Error, method, endpoint, err)
					return x, err
				}
			case "deflate":
				body, err = readDeflate(resp)
				if err != nil {
					lf("%v: %s %s - %s", log.Error, method, endpoint, err)
					return x, err
				}
			default:
				return x, fmt.Errorf("unsupported Content-Encoding: %s", ce)
			}
		} else {
			body, err = readUncompressed(resp)
			if err != nil {
				lf("%v: %s %s - %s", log.Error, method, endpoint, err)
				return x, err
			}
		}
	}

	// Store ETag for later retrieval
	if canOrShouldStore && rp.ReturnBodyOn304 && resp.StatusCode != http.StatusNotModified {
		if etag := resp.Header.Get("ETag"); etag != "" {
			err = rs.Set(
				endpoint,
				MetaData{
					ETag:        etag,
					Body:        body,
					ContentType: ct,
				})
			if err != nil {
				// Response cache failures are logged but do not cause ExecuteApi to fail.
				lf("%v: %s %s - %s", log.Error, method, endpoint, err)
			}
		}
	}

	if len(body) == 0 {
		return x, nil
	}

	// Type-specific return
	switch any(x).(type) {
	case []byte:
		return any(body).(T), nil
	default:
		switch ct {
		case "application/json":
			err = json.Unmarshal(body, &x)
			if err != nil {
				lf("%v: %s %s - %s", log.Error, method, endpoint, err)
			}
			return x, err
		case "text/xml", "application/xml":
			err = xml.Unmarshal(body, &x)
			if err != nil {
				lf("%v: %s %s - %s", log.Error, method, endpoint, err)
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
		if len(m) < 3 {
			rd.Result.AddRawMsg("%s", m)
			continue
		}
		msgType := m[0:3]
		msg := m[3:]
		msg = strings.TrimPrefix(msg, ":")
		msg = strings.TrimSpace(msg)
		if strings.HasPrefix(msg, "[") {
			if endBr := strings.Index(msg, "]"); endBr != -1 {
				rd.Prefix = msg[1:endBr]
				msg = strings.TrimSpace(msg[endBr+1:])
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
// Should be called during application initialization before
// concurrent requests are issued.
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

// SetResponseStore configures the shared response cache.
// Should be called during application initialization before
// concurrent requests are issued.
func SetResponseStore(store ResponseStorage) {
	rs = store
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
	useBody := (c1 != furlenc && !*isMultiPart) && (method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete || method == http.MethodPatch)
	if !useBody || r.Body == nil {
		return nil
	}

	// single read, no closure, no extra empty slice
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
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

func readUncompressed(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if !(errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
			return nil, fmt.Errorf("read failed: %w", err)
		}
	}
	return body, nil
}

func readGzip(resp *http.Response) ([]byte, error) {
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	defer gzr.Close()

	body, err := io.ReadAll(gzr) // single growing buffer
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	return body, nil
}

func readBrotli(resp *http.Response) ([]byte, error) {
	gzr := br.NewReader(resp.Body)
	body, err := io.ReadAll(gzr)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	return body, nil
}

func readDeflate(resp *http.Response) ([]byte, error) {
	dfr, err := zlib.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	defer dfr.Close()
	body, err := io.ReadAll(dfr)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	return body, nil
}

func compressGzip(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := gw.Write(src); err != nil {
		gw.Close()
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func determineContentType(resp *http.Response, req *http.Request, rp *RequestParam) string {
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = rp.AssumedContentType
	}
	if ct == "" {
		ct = req.Header.Get("Content-Type")
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}
