package nizk

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
	"golang.org/x/crypto/sha3"
)

type equationCacheKey struct {
	paramsID string
	rootHash [32]byte
}

type equationCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[equationCacheKey]*UnifiedEquation
	order    []equationCacheKey
}

func newEquationCache(capacity int) *equationCache {
	return &equationCache{
		capacity: capacity,
		entries:  make(map[equationCacheKey]*UnifiedEquation),
		order:    make([]equationCacheKey, 0, capacity),
	}
}

func (c *equationCache) Get(key equationCacheKey) (*UnifiedEquation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	eq, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	c.touchLocked(key)
	return eq, true
}

func (c *equationCache) Add(key equationCacheKey, eq *UnifiedEquation) {
	if c == nil || c.capacity == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok {
		c.entries[key] = eq
		if existing != eq {
			c.touchLocked(key)
		}
		return
	}
	if len(c.order) >= c.capacity {
		evict := c.order[0]
		copy(c.order, c.order[1:])
		c.order = c.order[:len(c.order)-1]
		delete(c.entries, evict)
	}
	c.entries[key] = eq
	c.order = append(c.order, key)
}

func (c *equationCache) touchLocked(key equationCacheKey) {
	for i, cached := range c.order {
		if cached == key {
			copy(c.order[i:], c.order[i+1:])
			c.order[len(c.order)-1] = key
			return
		}
	}
}

var verifierEquationCache = newEquationCache(8)

func buildEquationCacheKey(params *lattice.PublicParameters, root *lattice.Vector) (equationCacheKey, bool) {
	if params == nil || root == nil {
		return equationCacheKey{}, false
	}
	return equationCacheKey{
		paramsID: paramsFingerprint(params),
		rootHash: hashVector(root),
	}, true
}

func paramsFingerprint(params *lattice.PublicParameters) string {
	if params == nil {
		return ""
	}
	return fmt.Sprintf("n=%d|m=%d|l=%d|me=%d|nk=%d|q=%d|beta=%d|kappa=%d",
		params.N,
		params.M,
		params.L,
		params.M_E,
		params.NK,
		params.Q,
		params.Beta,
		params.Kappa,
	)
}

func hashVector(v *lattice.Vector) [32]byte {
	var digest [32]byte
	if v == nil {
		return digest
	}
	hasher := sha3.New256()
	buf := make([]byte, 8)
	for i := 0; i < v.Size; i++ {
		binary.LittleEndian.PutUint64(buf, uint64(v.Data[i]))
		hasher.Write(buf)
	}
	sum := hasher.Sum(nil)
	copy(digest[:], sum)
	return digest
}
