package protocol7h3

import (
	"context"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// ReplayStore interface
// ---------------------------------------------------------------------------

// ReplayStore provides atomic nonce deduplication for replay protection.
//
// Check atomically marks a nonce as seen and reports whether it was already
// present:
//   - (false, nil) — nonce is fresh (first time seen)
//   - (true, nil)  — nonce is a replay (already seen)
//   - (_, err)     — store error; caller should fail closed
type ReplayStore interface {
	Check(ctx context.Context, key string, ttlMs int64) (bool, error)
}

// ---------------------------------------------------------------------------
// InMemoryReplayStore
// ---------------------------------------------------------------------------

type inMemoryEntry struct {
	expiresAt time.Time
}

// InMemoryReplayStore is a stdlib-only, process-local replay store backed by
// sync.Map with time-based expiry.  It does NOT provide cross-instance replay
// protection — use RedisReplayStore for multi-instance deployments.
type InMemoryReplayStore struct {
	entries sync.Map
	now     func() time.Time
}

// NewInMemoryReplayStore returns a new in-process replay store.
func NewInMemoryReplayStore() *InMemoryReplayStore {
	return &InMemoryReplayStore{now: time.Now}
}

// Check returns (false, nil) when the nonce is fresh and (true, nil) when it
// is a replay.  Expired entries are evicted lazily on access.
func (s *InMemoryReplayStore) Check(ctx context.Context, key string, ttlMs int64) (bool, error) {
	ttl := time.Duration(ttlMs) * time.Millisecond
	if ttl <= 0 {
		ttl = time.Millisecond
	}
	now := s.now()
	expiresAt := now.Add(ttl)

	actual, loaded := s.entries.LoadOrStore(key, &inMemoryEntry{expiresAt: expiresAt})
	if !loaded {
		// Key was freshly stored — this is the first time we've seen it.
		return false, nil
	}

	// Key already existed — check whether the stored entry is still live.
	entry := actual.(*inMemoryEntry)
	if now.After(entry.expiresAt) {
		// Expired: treat as fresh and refresh the expiry.
		s.entries.Store(key, &inMemoryEntry{expiresAt: expiresAt})
		return false, nil
	}

	// Entry is live — this is a replay.
	return true, nil
}

// ---------------------------------------------------------------------------
// RedisReplayStore — injection-based, zero external imports
// ---------------------------------------------------------------------------

// SetNXFunc is the injection point for Redis SET NX PX semantics.
//
// Implementations should:
//   - Return (true, nil)  when the key was newly set (fresh).
//   - Return (false, nil) when the key already existed (replay blocked by NX).
//   - Return (_, err)     on connection or protocol errors.
//
// Example adapter using go-redis:
//
//	func(ctx context.Context, key string, ttl time.Duration) (bool, error) {
//	    return rdb.SetNX(ctx, key, "1", ttl).Result()
//	}
type SetNXFunc func(ctx context.Context, key string, ttl time.Duration) (bool, error)

// RedisReplayStore delegates SET NX PX to an injected function, keeping this
// package free of any Redis client dependency.
type RedisReplayStore struct {
	prefix string
	setNX  SetNXFunc
}

// NewRedisReplayStore creates a RedisReplayStore.
//
// prefix is prepended to every nonce key (e.g. "7h3:nonce:").
// setNX is the injection function described by SetNXFunc.
func NewRedisReplayStore(prefix string, setNX SetNXFunc) *RedisReplayStore {
	return &RedisReplayStore{prefix: prefix, setNX: setNX}
}

// Check returns (false, nil) when the nonce is fresh, (true, nil) when it is
// a replay, or (false, err) on store error.
func (r *RedisReplayStore) Check(ctx context.Context, key string, ttlMs int64) (bool, error) {
	ttl := time.Duration(ttlMs) * time.Millisecond
	if ttl <= 0 {
		ttl = time.Millisecond
	}

	wasSet, err := r.setNX(ctx, r.prefix+key, ttl)
	if err != nil {
		return false, err
	}
	// wasSet=true → key newly set → fresh → not a replay
	// wasSet=false → key existed → replay
	return !wasSet, nil
}
