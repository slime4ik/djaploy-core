// Package ratelimit is a small thread safe rate limiter (flood protection).
// A fixed window in memory: reliable on a single instance and without dependencies.
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

// Allow returns true when the action is within the limit (max per period for this key).
// Over the limit it returns false (the action must be refused, for example with HTTP 429).
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

// cleanup drops stale windows every 10 minutes so the map does not grow forever.
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
