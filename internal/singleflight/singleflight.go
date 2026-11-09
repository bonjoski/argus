package singleflight

import "sync"

type call[T any] struct {
	wg  sync.WaitGroup
	val T
	err error
}

// Group coalesces concurrent duplicate calls for the same key so only one
// in-flight execution runs at a time while callers share its result.
type Group[T any] struct {
	mu sync.Mutex
	m  map[string]*call[T]
}

// Do executes fn once for a given key across concurrent callers, returning
// the shared result, error, and whether the result was shared across callers.
func (g *Group[T]) Do(key string, fn func() (T, error)) (T, error, bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call[T])
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err, true
	}

	c := new(call[T])
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		c.wg.Done()
		g.mu.Unlock()
	}()

	c.val, c.err = fn()
	return c.val, c.err, false
}
