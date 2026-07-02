package http

import (
	"container/list"
	"sync"
	"time"
)


type Metadata struct {
	ETag      string
	StoredAt  time.Time
	UpdatedAt time.Time
}

type entry struct {
	url  string
	meta Metadata
}

type cache struct {
	mu    sync.Mutex
	max   int
	items map[string]*list.Element
	lru   *list.List
}

func newCache(max int) *cache {
	if max <= 0 {
		max = 1000
	}

	return &cache{
		max:   max,
		items: make(map[string]*list.Element),
		lru:   list.New(),
	}
}

func (c *cache) Get(url string) (Metadata, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[url]
	if !ok {
		return Metadata{}, false
	}

	c.lru.MoveToFront(el)

	ent := el.Value.(*entry)
	return ent.meta, true
}

func (c *cache) Set(url string, meta Metadata) {
	if url == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	if el, ok := c.items[url]; ok {
		ent := el.Value.(*entry)

		if ent.meta.StoredAt.IsZero() {
			meta.StoredAt = now
		} else {
			meta.StoredAt = ent.meta.StoredAt
		}

		meta.UpdatedAt = now
		ent.meta = meta

		c.lru.MoveToFront(el)
		return
	}

	meta.StoredAt = now
	meta.UpdatedAt = now

	ent := &entry{
		url:  url,
		meta: meta,
	}

	el := c.lru.PushFront(ent)
	c.items[url] = el

	if c.lru.Len() > c.max {
		c.evictOldest()
	}
}

func (c *cache) evictOldest() {
	el := c.lru.Back()
	if el == nil {
		return
	}

	ent := el.Value.(*entry)

	delete(c.items, ent.url)
	c.lru.Remove(el)
}

func (c *cache) Delete(url string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[url]
	if !ok {
		return
	}

	delete(c.items, url)
	c.lru.Remove(el)
}

func (c *cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.lru.Init()
}

func (c *cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.lru.Len()
}
