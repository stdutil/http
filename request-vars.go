package http

import (
	"encoding/json"
	"errors"
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
		Valid         bool     // Indicates that the request has a valid JWT token
	}

	// RequestVars - contains necessary request variables
	RequestVars struct {
		Body      []byte            // The body of the request
		Cookies   map[string]string // Cookies included in the request
		HasBody   bool              // Indicates that the request has a body
		Method    string            // Method of the request
		Variables CustomVars        // Variables included in the request
		Token     *JWTInfo          // Access token
	}
)

// Errors
var (
	ErrRVNoBody = errors.New(`the request has no payload`)
)

// IsGet - a shortcut method to check if the request is a GET
func (rv *RequestVars) IsGet() bool {
	return rv.Method == "GET"
}

// IsPost is a shortcut method to check if the request is a POST
func (rv *RequestVars) IsPost() bool {
	return rv.Method == "POST"
}

// IsPut is a shortcut method to check if the request is a PUT
func (rv *RequestVars) IsPut() bool {
	return rv.Method == "PUT"
}

// IsDelete is a shortcut method to check if the request is a DELETE
func (rv *RequestVars) IsDelete() bool {
	return rv.Method == "DELETE"
}

// IsHead is a shortcut method to check if the request is a HEAD
func (rv *RequestVars) IsHead() bool {
	return rv.Method == "HEAD"
}

// IsOptions is a shortcut method to check if the request is OPTIONS
func (rv *RequestVars) IsOptions() bool {
	return rv.Method == "OPTIONS"
}

// IsPostOrPut is a shortcut method to check if the request is a POST or PUT
func (rv *RequestVars) IsPostOrPut() bool {
	return rv.Method == "POST" || rv.Method == "PUT"
}

// IsJSONGood checks if the request has body and attempts to marshal to Json
func (rv *RequestVars) IsJSONGood(v any) error {
	if !rv.HasBody {
		return ErrRVNoBody
	}
	if err := json.Unmarshal(rv.Body, &v); err != nil {
		return err
	}
	return nil
}
