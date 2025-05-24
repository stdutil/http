package http

import "maps"

type (
	// RequestParam for <REST verb>Api request functions
	RequestParam struct {
		TimeOut    int               // Request time out
		Compressed bool              // Compressed
		Headers    map[string]string // Headers for the request
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
