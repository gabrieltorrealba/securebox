package nonce

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// CounterSource: nonce = 4B prefix | 8B counter (big-endian)
// It is NOT safe to use the same prefix in different instances
// as it would lead to nonce reuse.
type CounterSource struct {
	Prefix  [4]byte
	mu      sync.Mutex
	Counter uint64
}

// NewCounter creates a new CounterSource with the given 4-byte prefix and starting counter value.
func NewCounter(prefix [4]byte, start uint64) *CounterSource {
	return &CounterSource{Prefix: prefix, Counter: start}
}

// Next generates the next nonce of the specified size.
// It returns an error if the requested size is not 12 bytes.
func (c *CounterSource) Next(size int) ([]byte, error) {
	if size != 12 {
		return nil, fmt.Errorf("CounterSource espera nonce de 12 bytes, got %d", size)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Counter++
	n := make([]byte, 12)
	copy(n[:4], c.Prefix[:])
	binary.BigEndian.PutUint64(n[4:], c.Counter)
	return n, nil
}

// Current returns the current counter value without incrementing it.
func (c *CounterSource) Current() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Counter
}
