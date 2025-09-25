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
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/go-chi/chi/v5"
	"github.com/stdutil/log"
	nv "github.com/stdutil/name-value"
	rslt "github.com/stdutil/result"
)

const (
	REQUEST_VERSION  string = "1.1.0.0"
	REQUEST_MODIFIED string = "24052025"
	MAX_BUFFER       int    = 1024
)

var (
	rto     int // Request timeout in seconds
	ct      *http.Transport
	logFunc func(string, ...any)
)

var (
	ErrRequestHasNoPayload = errors.New(`the request has no payload`)
	ErrInvalidAccessToken  = errors.New(`invalid access token`)
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

// ExecuteApi wraps http operation that change or read data and returns a byte array
//
// On headers:
//   - Content-Type: If this header is not set, it defaults to "application/json"
//   - Content-Encoding: If compressed is true, it is set to "gzip"
// func ExecuteApi[T any](method string, endPoint string, payload []byte, opts ...RequestOption) (T, error) {
// 	var x T

// 	rp := RequestParam{}
// 	for _, o := range opts {
// 		if o == nil {
// 			continue
// 		}
// 		o(&rp)
// 	}

// 	nr, err := http.NewRequest(method, endPoint, bytes.NewBuffer(payload))
// 	if err != nil {
// 		return x, err
// 	}
// 	nr.Close = true
// 	nr.Header.Set("User-Agent", fmt.Sprintf("com.github.stdutil.http/%s-%s", REQUEST_VERSION, REQUEST_MODIFIED))
// 	nr.Header.Set("Connection", "keep-alive")
// 	nr.Header.Set("Accept", "*/*")
// 	if ct := nr.Header.Get("Content-Type"); ct == "" {
// 		nr.Header.Set("Content-Type", "application/json")
// 	}
// 	if rp.Compressed {
// 		nr.Header.Set("Accept-Encoding", "gzip, deflate, br")
// 		switch strings.ToUpper(nr.Method) {
// 		case "POST", "PUT", "PATCH":
// 			nr.Header.Add("Content-Encoding", "gzip")
// 		}
// 	}
// 	for k, v := range rp.Headers {
// 		k = strings.ToLower(k)
// 		if k != "cookie" {
// 			nr.Header.Set(k, v)
// 			continue
// 		}
// 		for _, nvs := range strings.Split(v, `;`) {
// 			if nv := strings.Split(nvs, `=`); len(nv) > 1 {
// 				nr.AddCookie(&http.Cookie{
// 					Name:  strings.TrimSpace(nv[0]),
// 					Value: strings.TrimSpace(nv[1]),
// 				})
// 			}
// 		}
// 	}
// 	if rp.TimeOut == 0 {
// 		rp.TimeOut = 30
// 	}
// 	cli := http.Client{
// 		Timeout:   time.Second * time.Duration(rp.TimeOut),
// 		Transport: ct,
// 	}
// 	resp, err := cli.Do(nr)
// 	if err != nil {
// 		return x, err
// 	}
// 	defer resp.Body.Close()
// 	if resp.StatusCode != http.StatusOK {
// 		return x, fmt.Errorf(resp.Status)
// 	}
// 	var (
// 		data []byte
// 		xa   any
// 	)

// 	ce := strings.ToLower(resp.Header.Get("Content-Encoding"))
// 	if !resp.Uncompressed && ce == "gzip" {
// 		raw, err := io.ReadAll(resp.Body)
// 		if err != nil {
// 			return x, err
// 		}
// 		gzr, err := gzip.NewReader(bytes.NewBuffer(raw))
// 		if err != nil {
// 			return x, err
// 		}
// 		defer gzr.Close()
// 		for {
// 			uz := make([]byte, 1024)
// 			cnt, err := gzr.Read(uz)
// 			if err != nil {
// 				if !errors.Is(err, io.ErrUnexpectedEOF) {
// 					return x, err
// 				}
// 				break
// 			}
// 			if cnt == 0 {
// 				break
// 			}
// 			data = append(data, uz[0:cnt]...)
// 		}
// 		// Except for []bytes, unmarshal
// 		if reflect.TypeOf(x) == reflect.TypeOf([]byte{}) {
// 			xa = data
// 			return xa.(T), err
// 		}
// 		err = json.Unmarshal(data, &x)
// 		if err != nil {
// 			return x, err
// 		}
// 		return x, nil
// 	}

// 	data, err = io.ReadAll(resp.Body)
// 	if err != nil {
// 		if !errors.Is(err, io.ErrUnexpectedEOF) {
// 			return x, err
// 		}
// 	}
// 	if reflect.TypeOf(x) == reflect.TypeOf([]byte{}) {
// 		xa = data
// 		return xa.(T), err
// 	}
// 	err = json.Unmarshal(data, &x)
// 	if err != nil {
// 		return x, err
// 	}
// 	return x, nil
// }

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
	if rp.LogFunc != nil {
		logFunc = rp.LogFunc
	}

	// Create request
	req, err := http.NewRequest(method, endPoint, bytes.NewBuffer(payload))
	if err != nil {
		logFunc("%s: %s %s - %s", string(log.Error), method, endPoint, err)
		return x, err
	}

	// Default headers
	req.Header.Set("User-Agent", fmt.Sprintf("com.github.stdutil.http/%s-%s", REQUEST_VERSION, REQUEST_MODIFIED))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Accept", "*/*")

	for k, v := range rp.Headers {
		if k == "" || v == "" {
			continue
		}
		req.Header.Set(k, v)
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

	// Apply custom headers and cookies
	for k, v := range rp.Headers {
		if strings.EqualFold(k, "cookie") {
			for pair := range strings.SplitSeq(v, ";") {
				nv := strings.SplitN(pair, "=", 2)
				if len(nv) == 2 {
					req.AddCookie(&http.Cookie{
						Name:  strings.TrimSpace(nv[0]),
						Value: strings.TrimSpace(nv[1]),
					})
				}
			}
		} else {
			req.Header.Set(k, v)
		}
	}

	// HTTP client
	client := http.Client{
		Timeout:   time.Second * time.Duration(rp.TimeOut),
		Transport: ct,
	}
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("%s: Requesting resource at %s", err, endPoint)
		logFunc("%s: %s %s - %s", string(log.Error), method, endPoint, err)
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
		logFunc("%s: %s %s - %s", string(log.Error), method, endPoint, err)
		return x, err
	}

	// Decode response body
	var body []byte
	ce := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if !resp.Uncompressed && ce == "gzip" {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			logFunc("%s: %s %s - %s", string(log.Error), method, endPoint, err)
			return x, fmt.Errorf("read failed: %w", err)
		}
		gzr, err := gzip.NewReader(bytes.NewBuffer(raw))
		if err != nil {
			logFunc("%s: %s %s - %s", string(log.Error), method, endPoint, err)
			return x, fmt.Errorf("read failed: %w", err)
		}
		defer gzr.Close()
		body = make([]byte, 0, len(raw))
		for {
			uz := make([]byte, MAX_BUFFER)
			cnt, err := gzr.Read(uz)
			if err != nil {
				if !(errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
					logFunc("%s: %s %s - %s", string(log.Error), method, endPoint, err)
					return x, fmt.Errorf("read failed: %w", err)
				}
				break
			}
			if cnt == 0 {
				break
			}
			body = append(body, uz[0:cnt]...)
		}
	} else {
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			if !(errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
				logFunc("%s: %s %s - %s", string(log.Error), method, endPoint, err)
				return x, fmt.Errorf("read failed: %w", err)
			}
		}
	}

	// Type-specific return
	switch any(x).(type) {
	case []byte:
		return any(body).(T), nil
	default:
		ct := strings.ToLower(req.Header.Get("Content-Type"))
		if rp.AssumedContentType != "" {
			ct = rp.AssumedContentType
		}
		switch ct {
		case "application/json":
			err = json.Unmarshal(body, &x)
			if err != nil {
				logFunc("%s: %s %s - %s", string(log.Error), method, endPoint, err)
			}
			return x, err
		case "text/xml":
			err = xml.Unmarshal(body, &x)
			if err != nil {
				logFunc("%s: %s %s - %s", string(log.Error), method, endPoint, err)
			}
			return x, err
		case "plain/text":
			str, _ := any(string(body)).(T)
			return str, err
		}
		str, _ := any(body).(T)
		return str, nil
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
	rd.PageSize = trd.PageCount
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
	rv := &RequestVars{
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
	return *rv
}

// GetRequestVars requests variables and return JWT validation result
func GetRequestVars(r *http.Request, secretKey string, validateTimes, preserveCmdCase bool) (RequestVars, error) {
	rv := GetRequestVarsOnly(r, preserveCmdCase)
	rv.Token = nil
	// Silently ignore OPTIONS methid
	if strings.EqualFold(r.Method, "OPTIONS") {
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
	if err := json.Unmarshal(b, &v); err != nil {
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
	if len(secretKey) == 0 {
		return nil, fmt.Errorf(`secret key not set`)
	}
	var (
		pl  CustomPayload
		err error
	)

	skl := len(secretKey)
	if skl < 32 {
		secretKey += strings.Repeat("1", 32-skl)
	}

	// Parse JWT
	HMAC := jwt.NewHS256([]byte(secretKey))

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
	logFunc = f
}

// SetRequestTimeOut sets the new timeout value
func SetRequestTimeout(timeOut int) {
	rto = timeOut
}

// SignJwt builds a JWT token using HMAC256 algorithm
func SignJwt(claims *map[string]any, secretKey string) string {
	clm := *claims
	var (
		usr, dom, app, dev string
		iss, sub, jti, tnt string
		exp, nbf, iat      int
	)

	aud := jwt.Audience{}
	var ifc any
	if ifc = clm["iss"]; ifc != nil {
		iss = ifc.(string)
	}
	if ifc = clm["sub"]; ifc != nil {
		sub = ifc.(string)
	}
	if ifc = clm["aud"]; ifc != nil {
		t := reflect.TypeOf(ifc)

		// check if this is a slice
		if t.Kind() == reflect.Slice {
			// check if what type of slice are the elements
			if t.Elem().Kind() == reflect.String {
				aud = ifc.([]string)
			}
		}

		// check if this is a string
		if t.Kind() == reflect.String {
			aud = jwt.Audience([]string{ifc.(string)})
		}
	}
	if ifc = clm["exp"]; ifc != nil {
		exp = ifc.(int)
	}
	if ifc = clm["nbf"]; ifc != nil {
		nbf = ifc.(int)
	}
	if ifc = clm["iat"]; ifc != nil {
		iat = ifc.(int)
	}
	if ifc = clm["usr"]; ifc != nil {
		usr = ifc.(string)
	}
	if ifc = clm["dom"]; ifc != nil {
		dom = ifc.(string)
	}
	if ifc = clm["app"]; ifc != nil {
		app = ifc.(string)
	}
	if ifc = clm["dev"]; ifc != nil {
		dev = ifc.(string)
	}
	if ifc = clm["jti"]; ifc != nil {
		jti = ifc.(string)
	}
	if ifc = clm["tnt"]; ifc != nil {
		tnt = ifc.(string)
	}

	unixt := func(unixts int64) *jwt.Time {
		epoch := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
		tt := time.Unix(unixts, 0)
		if tt.Before(epoch) {
			tt = epoch
		}
		return &jwt.Time{Time: tt}
	}

	pl := CustomPayload{
		Payload: jwt.Payload{
			Issuer:         iss,
			Subject:        sub,
			Audience:       aud,
			ExpirationTime: unixt(int64(exp)),
			NotBefore:      unixt(int64(nbf)),
			IssuedAt:       unixt(int64(iat)),
			JWTID:          jti,
		},
		UserName:      usr,
		Domain:        dom,
		ApplicationID: app,
		DeviceID:      dev,
		TenantID:      tnt,
	}

	skl := len(secretKey)
	if skl < 32 {
		secretKey += strings.Repeat("1", 32-skl)
	}

	HMAC := jwt.NewHS256([]byte(secretKey))
	token, err := jwt.Sign(pl, HMAC)
	if err != nil {
		return ""
	}

	return string(token)
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
		return nil, fmt.Errorf(`authorization header not set`)
	}
	if jwtp = strings.Split(jwth, " "); len(jwtp) < 2 {
		return nil, fmt.Errorf(`invalid authorization header`)
	}
	if !strings.EqualFold(strings.TrimSpace(jwtp[0]), "bearer") {
		return nil, fmt.Errorf(`invalid authorization bearer`)
	}
	if jwtfromck = strings.TrimSpace(jwtp[1]); len(jwtfromck) == 0 {
		return nil, fmt.Errorf(`invalid authorization token`)
	}
	return ParseJwt(jwtfromck, secretKey, validateTimes)
}

func getBody(r *http.Request, isMultiPart *bool) []byte {
	var (
		body []byte
		c1   string
	)
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
	if useBody := (c1 != furlenc && !*isMultiPart) && (method == "POST" || method == "PUT" || method == "DELETE"); useBody {
		// We are receiving body as bytes to Unmarshall later depending on the type
		b := func() []byte {
			if r.Body != nil {
				b, _ := io.ReadAll(r.Body)
				defer r.Body.Close()
				return b
			}
			return []byte{}
		}
		body = b()
	}
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
