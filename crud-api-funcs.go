package http

import (
	"encoding/json"

	rslt "github.com/stdutil/result"
)

// CreateApi posts data on an API endpoint and converts the returned data into a resulting type
func CreateApi[T any, U any](url string, pl U, opts ...RequestOption) rslt.ResultAny[T] {
	b, err := json.Marshal(pl)
	if err != nil {
		return rslt.ResultAny[T]{
			Result: rslt.InitResult(
				rslt.WithMessage(err.Error()),
			),
		}
	}
	opts = append(opts, Compressed(false)) // last one will override
	rd := ExecuteJsonApi("POST", url, b, opts...)
	return getJsonConverted[T](&rd)
}

// ReadApi retrieves data on an API endpoint and converts the returned data into a resulting type
func ReadApi[T any](url string, opts ...RequestOption) rslt.ResultAny[T] {
	opts = append(opts, Compressed(true)) // last one will override
	rd := ExecuteJsonApi("GET", url, nil, opts...)
	return getJsonConverted[T](&rd)
}

// UpdateApi updates data on an API endpoint and converts the returned data into a resulting type
func UpdateApi[T any, U any](url string, pl U, opts ...RequestOption) rslt.ResultAny[T] {
	b, err := json.Marshal(pl)
	if err != nil {
		return rslt.ResultAny[T]{
			Result: rslt.InitResult(rslt.WithMessage(err.Error())),
		}
	}
	opts = append(opts, Compressed(false)) // last one will override
	rd := ExecuteJsonApi("PUT", url, b, opts...)
	return getJsonConverted[T](&rd)
}

// DeleteApi deletes data on an API endpoint and converts the returned data into a resulting type
func DeleteApi[T any](url string, opts ...RequestOption) rslt.ResultAny[T] {
	opts = append(opts, Compressed(false)) // last one will override
	rd := ExecuteJsonApi("DELETE", url, nil, opts...)
	return getJsonConverted[T](&rd)
}

// PatchApi patches data on an API endpoint and converts the returned data into a resulting type
func PatchApi[T any, U any](url string, pl U, opts ...RequestOption) rslt.ResultAny[T] {
	b, err := json.Marshal(pl)
	if err != nil {
		return rslt.ResultAny[T]{
			Result: rslt.InitResult(rslt.WithMessage(err.Error())),
		}
	}
	opts = append(opts, Compressed(false)) // last one will override
	rd := ExecuteJsonApi("PATCH", url, b, opts...)
	return getJsonConverted[T](&rd)
}
