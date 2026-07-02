package http

var defaultCache = newCache(1000)

func SetETag(url, etag string) {
	defaultCache.Set(url, Metadata{
		ETag: etag,
	})
}

func GetMetadata(url string) (Metadata, bool) {
	return defaultCache.Get(url)
}

func ShouldSendIfNoneMatch(url string) (etag string, ok bool) {
	meta, found := defaultCache.Get(url)
	if !found || meta.ETag == "" {
		return "", false
	}

	return meta.ETag, true
}

func Delete(url string) {
	defaultCache.Delete(url)
}

func Clear() {
	defaultCache.Clear()
}

func Len() int {
	return defaultCache.Len()
}
