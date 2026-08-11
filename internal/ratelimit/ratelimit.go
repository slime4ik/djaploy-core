// Package ratelimit is a small thread safe rate limiter used as flood protection.
// It is a fixed window kept in memory, which is reliable on a single instance and pulls in no
// dependencies.
package ratelimit

import (
	"sync"
	"time"
)

type window struct {
	count int
	reset time.Time
}

type Limiter struct {
	mu   sync.Mutex
	hits map[string]*window
}

func New() *Limiter {
	l := &Limiter{hits: make(map[string]*window)}
	go l.cleanup()
	return l
}

// Allow reports whether the action fits the limit (max per window, for this key).
// Once the limit is exceeded it returns false and the caller rejects the action, for example with
// HTTP 429.
func (l *Limiter) Allow(key string, max int, per time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w := l.hits[key]
	if w == nil || now.After(w.reset) {
		l.hits[key] = &window{count: 1, reset: now.Add(per)}
		return true
	}
	if w.count >= max {
		return false
	}
	w.count++
	return true
}

// cleanup drops expired windows every 10 minutes so the map does not grow forever.
func (l *Limiter) cleanup() {
	for range time.Tick(10 * time.Minute) {
		l.mu.Lock()
		now := time.Now()
		for k, w := range l.hits {
			if now.After(w.reset) {
				delete(l.hits, k)
			}
		}
		l.mu.Unlock()
	}
}
