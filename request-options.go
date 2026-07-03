package http

import "maps"

type (
	// RequestParam for <REST verb>Api request functions
	RequestParam struct {
		TimeOut            int                  // Request time out
		Compressed         bool                 // Compressed
		Headers            map[string]string    // Headers for the request
		LogFunc            func(string, ...any) // Log function
		AssumedContentType string               // Assumed response body content type
		ReturnBodyOn304    bool                 // Return response on 304 Not Modified
	}
	// RequestOption for <REST verb>Api request functions
	RequestOption func(opt *RequestParam) error
)

// TimeOut sets the request timeout as an option
//
// This is used with <REST verb>Api functions
func TimeOut(timeOut int) RequestOption {
	return func(rp *RequestParam) error {
		rp.TimeOut = timeOut
		return nil
	}
}

// Compressed sets the request compression as an option
//
// This is used with <REST verb>Api functions
func Compressed(compressed bool) RequestOption {
	return func(rp *RequestParam) error {
		rp.Compressed = compressed
		return nil
	}
}

// Headers adds request headers as an option
//
// This is used with <REST verb>Api functions
func Headers(hdr map[string]string) RequestOption {
	return func(rp *RequestParam) error {
		if rp.Headers == nil {
			rp.Headers = make(map[string]string)
		}
		maps.Copy(rp.Headers, hdr)
		return nil
	}
}

// Header adds a single header to the request
//
// This is used with <REST verb>Api functions
func Header(k, v string) RequestOption {
	return func(rp *RequestParam) error {
		rp.Headers[k] = v
		return nil
	}
}

// Log sets the log function that executes on ExecuteAPI calls
//
// This is used with <REST verb>Api functions
func Log(f func(string, ...any)) RequestOption {
	return func(rp *RequestParam) error {
		rp.LogFunc = f
		return nil
	}
}

// AssumedContentType sets the response body content type to automatically convert to generic type
//
// This is used with <REST verb>Api functions
func AssumedContentType(ct string) RequestOption {
	return func(rp *RequestParam) error {
		rp.AssumedContentType = ct
		return nil
	}
}

// ReturnBodyOn304 sets whether to return the response body on 304 Not Modified
//
// This is used with <REST verb>Api functions
func ReturnBodyOn304(returnBody bool) RequestOption {
	return func(rp *RequestParam) error {
		rp.ReturnBodyOn304 = returnBody
		return nil
	}
}
