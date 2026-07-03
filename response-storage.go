package http

type ResponseStorage interface {
	Get(key string) (MetaData, bool)
	Set(key string, meta MetaData) error
	Delete(key string) error
}
