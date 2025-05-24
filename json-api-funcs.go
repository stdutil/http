package http

import "sync"

// GetJson wraps http.Get and gets a raw json message data
func GetJson(endpoint string, headers map[string]string, rw *sync.RWMutex) ResultData {
	return ExecuteJsonApi("GET", endpoint, nil, Headers(headers), TimeOut(rto))
}

// DeleteJson wraps http.Delete and gets a raw json message data
func DeleteJson(endpoint string, headers map[string]string, rw *sync.RWMutex) ResultData {
	return ExecuteJsonApi("DELETE", endpoint, nil, Headers(headers), TimeOut(rto))
}

// PostJson wraps http.Post and gets a raw json message data
func PostJson(endpoint string, payload []byte, gzipped bool, headers map[string]string, rw *sync.RWMutex) ResultData {
	return ExecuteJsonApi("POST", endpoint, payload, Compressed(gzipped), Headers(headers), TimeOut(rto))
}

// PutJson wraps http.Put and gets a raw json message data
func PutJson(endpoint string, payload []byte, gzipped bool, headers map[string]string, rw *sync.RWMutex) ResultData {
	return ExecuteJsonApi("PUT", endpoint, payload, Compressed(gzipped), Headers(headers), TimeOut(rto))
}

// PatchJson wraps http.Patch and gets a raw json message data
func PatchJson(endpoint string, payload []byte, gzipped bool, headers map[string]string, rw *sync.RWMutex) ResultData {
	return ExecuteJsonApi("PATCH", endpoint, payload, Compressed(gzipped), Headers(headers), TimeOut(rto))
}
