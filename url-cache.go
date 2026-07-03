package http

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

type MetaData struct {
	ETag        string
	Body        []byte
	ContentType string
	StoredAt    time.Time
	UpdatedAt   time.Time
}

type entry struct {
	url  string
	meta MetaData
}

type URLCache struct {
	mu             sync.Mutex
	maxItems       int
	maxSizePerItem int64
	maxTotalSize   int64
	currentSize    int64
	items          map[string]*list.Element
	lru            *list.List
}

func NewURLCache(maxItems int, maxSizePerItem, maxTotalSize int64) *URLCache {
	if maxItems <= 0 {
		maxItems = 500
	}
	if maxSizePerItem <= 0 {
		maxSizePerItem = 256 * 1024
	}
	if maxTotalSize <= 0 {
		maxTotalSize = 20 * 1024 * 1024
	}

	return &URLCache{
		maxSizePerItem: maxSizePerItem,
		maxTotalSize:   maxTotalSize,
		maxItems:       maxItems,
		items:          make(map[string]*list.Element),
		lru:            list.New(),
	}
}

func (c *URLCache) Get(url string) (MetaData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[url]
	if !ok {
		return MetaData{}, false
	}

	c.lru.MoveToFront(el)

	ent := el.Value.(*entry)
	meta := ent.meta
	meta.Body = append([]byte(nil), ent.meta.Body...)

	return meta, true
}

func (c *URLCache) Set(url string, meta MetaData) error {
	if url == "" {
		return fmt.Errorf("url is empty")
	}

	metaLen := int64(len(meta.Body))
	if metaLen > c.maxSizePerItem {
		return fmt.Errorf("meta body too large")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	meta.Body = append([]byte(nil), meta.Body...)
	meta.UpdatedAt = now

	if el, ok := c.items[url]; ok {
		ent := el.Value.(*entry)

		oldLen := int64(len(ent.meta.Body))
		newSize := c.currentSize - oldLen + metaLen

		for newSize > c.maxTotalSize {
			oldest := c.lru.Back()
			if oldest == nil || oldest == el {
				return fmt.Errorf("cache size exceeded")
			}

			c.evictElement(oldest)
			newSize = c.currentSize - oldLen + metaLen
		}

		if ent.meta.StoredAt.IsZero() {
			meta.StoredAt = now
		} else {
			meta.StoredAt = ent.meta.StoredAt
		}

		c.currentSize = c.currentSize - oldLen + metaLen
		ent.meta = meta
		c.lru.MoveToFront(el)

		return nil
	}

	for c.lru.Len() >= c.maxItems {
		c.evictOldest()
	}

	for c.currentSize+metaLen > c.maxTotalSize {
		if c.lru.Len() == 0 {
			return fmt.Errorf("cache size exceeded")
		}
		c.evictOldest()
	}

	meta.StoredAt = now

	ent := &entry{
		url:  url,
		meta: meta,
	}

	el := c.lru.PushFront(ent)
	c.items[url] = el
	c.currentSize += metaLen

	return nil
}

func (c *URLCache) evictOldest() {
	el := c.lru.Back()
	if el == nil {
		return
	}

	c.evictElement(el)
}

func (c *URLCache) evictElement(el *list.Element) {
	ent := el.Value.(*entry)

	delete(c.items, ent.url)
	c.lru.Remove(el)
	c.currentSize -= int64(len(ent.meta.Body))

	if c.currentSize < 0 {
		c.currentSize = 0
	}
}

func (c *URLCache) Delete(url string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[url]
	if !ok {
		return nil
	}

	c.evictElement(el)
	return nil
}

func (c *URLCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.lru.Init()
	c.currentSize = 0
}

func (c *URLCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.lru.Len()
}
