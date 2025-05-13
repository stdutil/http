package http

import (
	"strconv"

	nv "github.com/stdutil/name-value"
)

// CustomVars - command struct
type CustomVars struct {
	Command        []string      // Commands represents the sub-paths in the URL request
	Key            string        // The key of the the request
	QueryString    nv.NameValues // The query string values of the URL request
	HasQueryString bool          // Indicates that the URL request has a query string
	FormData       nv.NameValues // The form values associated with the URL request, usually appear when the method is POST and PUT
	HasFormData    bool          // Indicates that the URL request has form data
	IsMultipart    bool          // Indicates that the URL request is a multi part request
	DecodedCommand nv.NameValues // Decoded commands from an encrypted values represented by q query string
}
type KeyTypes interface {
	string | int | int64
}

// FirstCommand - get first command from route
func (cv CustomVars) FirstCommand() string {
	_, ret := cv.GetCommand(0)
	return ret
}

// SecondCommand - get second command from route
func (cv CustomVars) SecondCommand() string {
	_, ret := cv.GetCommand(1)
	return ret
}

// ThirdCommand - get third command from route
func (cv CustomVars) ThirdCommand() string {
	_, ret := cv.GetCommand(2)
	return ret
}

// LastCommand - get third command from route
func (cv CustomVars) LastCommand() string {
	_, ret := cv.GetCommand(uint(len(cv.Command) - 1))
	return ret
}

// GetCommand - get command by index
func (cv CustomVars) GetCommand(index uint) (exists bool, value string) {
	lenc := uint(len(cv.Command))
	// if there's no command, return at once
	if lenc == 0 {
		return false, ""
	}
	// if the index is greater than the length of the array
	if index > lenc-1 {
		return false, ""
	}
	return true, cv.Command[index]
}

// RouteID extracts and converts a key from CustomVars to the desired type T.
func RouteID[T KeyTypes](cv *CustomVars) T {
	switch any(*new(T)).(type) {
	case string:
		return any(cv.Key).(T)
	case int:
		v, _ := strconv.Atoi(cv.Key)
		return any(v).(T)
	case int64:
		v, _ := strconv.ParseInt(cv.Key, 10, 64)
		return any(v).(T)
	default:
		var zero T
		return zero
	}
}
