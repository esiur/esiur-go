package resource

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store is a resource that keeps other resources and resolves their links. A store is put at a
// one-segment path ("sys") that becomes the first segment of the links of everything it keeps
// ("sys/greeter").
type Store interface {
	Resource
	// Get returns the resource kept at path (relative to the store), or nil.
	Get(ctx context.Context, path string) (Resource, error)
	// Put keeps r at path (relative to the store).
	Put(ctx context.Context, r Resource, path string) error
	// Link is the path of r within this store.
	Link(r Resource) string
	// Modify is told that a kept resource's property index changed; a persistent store writes
	// it down.
	Modify(r Resource, index int, value any, age uint64, date time.Time)
	// Remove forgets r; false if this store was not keeping it.
	Remove(ctx context.Context, r Resource) (bool, error)
}

// MemoryStore keeps its resources in memory. Besides its links, a resource can be resolved as
// "$<instance id>".
type MemoryStore struct {
	Base
	mu        sync.Mutex
	resources map[uint32]Resource
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{resources: map[uint32]Resource{}} }

func (s *MemoryStore) Link(r Resource) string {
	i := InstanceOf(r)
	if i == nil || any(i.Store) != any(s) {
		return ""
	}
	link, _ := i.Variable("link")
	str, _ := link.(string)
	return str
}

func (s *MemoryStore) Get(_ context.Context, path string) (Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.HasPrefix(path, "$") {
		id, err := strconv.ParseUint(path[1:], 10, 32)
		if err != nil {
			return nil, nil
		}
		return s.resources[uint32(id)], nil
	}
	for _, r := range s.resources {
		if s.Link(r) == path {
			return r, nil
		}
	}
	return nil, nil
}

func (s *MemoryStore) Put(_ context.Context, r Resource, path string) error {
	i := InstanceOf(r)
	i.SetVariable("link", path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resources == nil {
		s.resources = map[uint32]Resource{}
	}
	s.resources[i.ID] = r
	return nil
}

func (s *MemoryStore) Modify(Resource, int, any, uint64, time.Time) {}

func (s *MemoryStore) Remove(_ context.Context, r Resource) (bool, error) {
	i := InstanceOf(r)
	if i == nil || any(i.Store) != any(s) {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.resources[i.ID]
	delete(s.resources, i.ID)
	return ok, nil
}
