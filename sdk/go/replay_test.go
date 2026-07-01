package protocol7h3

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestInMemoryReplayStore_Fresh(t *testing.T) {
	store := NewInMemoryReplayStore()
	ctx := context.Background()

	replay, err := store.Check(ctx, "nonce-1", 30_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if replay {
		t.Error("expected fresh (false) on first call, got true")
	}
}

func TestInMemoryReplayStore_Replay(t *testing.T) {
	store := NewInMemoryReplayStore()
	ctx := context.Background()

	if _, err := store.Check(ctx, "nonce-2", 30_000); err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}

	replay, err := store.Check(ctx, "nonce-2", 30_000)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if !replay {
		t.Error("expected replay (true) on second call with same nonce, got false")
	}
}

func TestInMemoryReplayStore_ExpiredEntryTreatedAsFresh(t *testing.T) {
	var mu sync.Mutex
	now := time.Now()
	store := &InMemoryReplayStore{
		now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		},
	}
	ctx := context.Background()

	// First call: set nonce with 100ms TTL
	replay, err := store.Check(ctx, "nonce-exp", 100)
	if err != nil || replay {
		t.Fatalf("expected fresh on first call; replay=%v err=%v", replay, err)
	}

	// Advance past TTL
	mu.Lock()
	now = now.Add(200 * time.Millisecond)
	mu.Unlock()

	// Second call: expired entry should be treated as fresh
	replay, err = store.Check(ctx, "nonce-exp", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if replay {
		t.Error("expected fresh (false) after TTL expiry, got true")
	}
}

func TestInMemoryReplayStore_DistinctNonces(t *testing.T) {
	store := NewInMemoryReplayStore()
	ctx := context.Background()

	for _, nonce := range []string{"a", "b", "c"} {
		replay, err := store.Check(ctx, nonce, 60_000)
		if err != nil || replay {
			t.Errorf("nonce %q: expected fresh; replay=%v err=%v", nonce, replay, err)
		}
	}
}

func TestRedisReplayStore_Fresh(t *testing.T) {
	// setNX returns true = key was newly set = fresh
	setNX := func(_ context.Context, _ string, _ time.Duration) (bool, error) {
		return true, nil
	}
	store := NewRedisReplayStore("7h3:nonce:", setNX)
	replay, err := store.Check(context.Background(), "nonce-r1", 30_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if replay {
		t.Error("expected fresh (false) when setNX returns true")
	}
}

func TestRedisReplayStore_Replay(t *testing.T) {
	// setNX returns false = key already existed = replay
	setNX := func(_ context.Context, _ string, _ time.Duration) (bool, error) {
		return false, nil
	}
	store := NewRedisReplayStore("7h3:nonce:", setNX)
	replay, err := store.Check(context.Background(), "nonce-r2", 30_000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !replay {
		t.Error("expected replay (true) when setNX returns false")
	}
}

func TestRedisReplayStore_KeyPrefix(t *testing.T) {
	var capturedKey string
	setNX := func(_ context.Context, key string, _ time.Duration) (bool, error) {
		capturedKey = key
		return true, nil
	}
	store := NewRedisReplayStore("custom:prefix:", setNX)
	_, _ = store.Check(context.Background(), "my-nonce", 5000)

	if capturedKey != "custom:prefix:my-nonce" {
		t.Errorf("expected key 'custom:prefix:my-nonce', got %q", capturedKey)
	}
}

func TestRedisReplayStore_TTLClamped(t *testing.T) {
	var capturedTTL time.Duration
	setNX := func(_ context.Context, _ string, ttl time.Duration) (bool, error) {
		capturedTTL = ttl
		return true, nil
	}
	store := NewRedisReplayStore("p:", setNX)
	_, _ = store.Check(context.Background(), "n", 0)

	if capturedTTL < time.Millisecond {
		t.Errorf("TTL should be clamped to at least 1ms, got %v", capturedTTL)
	}
}

func TestRedisReplayStore_ImplementsInterface(t *testing.T) {
	setNX := func(_ context.Context, _ string, _ time.Duration) (bool, error) {
		return true, nil
	}
	var _ ReplayStore = NewRedisReplayStore("p:", setNX)
	var _ ReplayStore = NewInMemoryReplayStore()
}
