// Package ratelimit provides rate limiting functionality for login attempts.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter tracks failed login attempts and blocks excessive attempts.
type Limiter struct {
	mu sync.RWMutex

	maxAttempts    int
	windowDuration time.Duration
	blockDuration  time.Duration

	// attempts tracks failed attempts per key (IP or username)
	attempts map[string]*attemptRecord

	stopCleanup chan struct{}
}

// attemptRecord tracks attempts for a single key.
type attemptRecord struct {
	count     int
	firstAt   time.Time
	blockedAt time.Time
}

// Config holds rate limiter configuration.
type Config struct {
	// MaxAttempts is the maximum number of failed attempts in the window
	MaxAttempts int
	// WindowDuration is the time window for counting attempts
	WindowDuration time.Duration
	// BlockDuration is how long to block after exceeding max attempts
	BlockDuration time.Duration
}

// New creates a new rate limiter.
func New(cfg Config) *Limiter {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = 15 * time.Minute
	}
	if cfg.BlockDuration <= 0 {
		cfg.BlockDuration = 15 * time.Minute
	}

	l := &Limiter{
		maxAttempts:    cfg.MaxAttempts,
		windowDuration: cfg.WindowDuration,
		blockDuration:  cfg.BlockDuration,
		attempts:       make(map[string]*attemptRecord),
		stopCleanup:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go l.cleanupLoop()

	return l
}

// Close stops the limiter's cleanup goroutine.
func (l *Limiter) Close() {
	close(l.stopCleanup)
}

// IsBlocked returns true if the key is currently blocked.
func (l *Limiter) IsBlocked(key string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	record, exists := l.attempts[key]
	if !exists {
		return false
	}

	// Check if blocked
	if !record.blockedAt.IsZero() {
		if time.Since(record.blockedAt) < l.blockDuration {
			return true
		}
	}

	return false
}

// RecordFailure records a failed attempt for the given key.
// Returns true if the key is now blocked.
func (l *Limiter) RecordFailure(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	record, exists := l.attempts[key]
	if !exists {
		l.attempts[key] = &attemptRecord{
			count:   1,
			firstAt: now,
		}
		return false
	}

	// Check if window has expired, reset if so
	if time.Since(record.firstAt) > l.windowDuration {
		record.count = 1
		record.firstAt = now
		record.blockedAt = time.Time{}
		return false
	}

	// Increment count
	record.count++

	// Check if should block
	if record.count >= l.maxAttempts {
		record.blockedAt = now
		return true
	}

	return false
}

// RecordSuccess clears the failure record for the given key.
func (l *Limiter) RecordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.attempts, key)
}

// RemainingAttempts returns how many attempts remain before blocking.
func (l *Limiter) RemainingAttempts(key string) int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	record, exists := l.attempts[key]
	if !exists {
		return l.maxAttempts
	}

	// Check if window has expired
	if time.Since(record.firstAt) > l.windowDuration {
		return l.maxAttempts
	}

	remaining := l.maxAttempts - record.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// BlockedUntil returns when the block expires, or zero time if not blocked.
func (l *Limiter) BlockedUntil(key string) time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()

	record, exists := l.attempts[key]
	if !exists {
		return time.Time{}
	}

	if record.blockedAt.IsZero() {
		return time.Time{}
	}

	unblockAt := record.blockedAt.Add(l.blockDuration)
	if time.Now().After(unblockAt) {
		return time.Time{}
	}

	return unblockAt
}

// cleanupLoop periodically removes expired records.
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCleanup:
			return
		case <-ticker.C:
			l.cleanup()
		}
	}
}

// cleanup removes expired attempt records.
func (l *Limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	expireAfter := l.windowDuration + l.blockDuration

	for key, record := range l.attempts {
		// Remove if both window and block have expired
		age := now.Sub(record.firstAt)
		if age > expireAfter {
			delete(l.attempts, key)
		}
	}
}
