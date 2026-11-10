package resource

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"sync"

	"github.com/esiur/esiur-go/data"
	"github.com/esiur/esiur-go/security"
)

// Evaluation is the verdict of the permissions managers on one operation.
type Evaluation struct {
	Allowed bool
	Reason  string
}

// Warehouse owns the resources of a node. Put stores in first, then resources into them; a
// peer reaches a resource by its link ("sys/greeter") or its instance id.
//
//	w := resource.NewWarehouse(nil)
//	w.Put(ctx, "sys", resource.NewMemoryStore())
//	w.Put(ctx, "sys/greeter", &Greeter{})
//	w.Open(ctx)
type Warehouse struct {
	// Registry holds the record and enum definitions exported types may refer to.
	Registry *data.TypeRegistry

	mu          sync.Mutex
	resources   map[uint32]Resource
	stores      []Store
	counter     uint32
	opened      bool
	typesByGo   map[reflect.Type]*HostedType
	typesByID   map[uint64]*HostedType
	typeCounter uint64
	permissions []security.PermissionsManager
	auth        map[string]security.AuthProvider
	encryption  map[string]security.EncryptionProvider
	encOrder    []string
}

// NewWarehouse returns an empty warehouse; registry may be nil.
func NewWarehouse(registry *data.TypeRegistry) *Warehouse {
	return &Warehouse{
		Registry:   registry,
		resources:  map[uint32]Resource{},
		typesByGo:  map[reflect.Type]*HostedType{},
		typesByID:  map[uint64]*HostedType{},
		auth:       map[string]security.AuthProvider{},
		encryption: map[string]security.EncryptionProvider{},
	}
}

// ---- authentication and encryption providers ---------------------------------------------

// RegisterAuthenticationProvider lets peers authenticate with provider, selected by its
// protocol name.
func (w *Warehouse) RegisterAuthenticationProvider(provider security.AuthProvider) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.auth[provider.Name()] = provider
}

// AuthenticationProvider returns the provider registered for a protocol name.
func (w *Warehouse) AuthenticationProvider(name string) security.AuthProvider {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.auth[name]
}

// RegisterEncryptionProvider lets connections encrypt with provider, negotiated by its name.
func (w *Warehouse) RegisterEncryptionProvider(provider security.EncryptionProvider) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, taken := w.encryption[provider.Name()]; taken {
		return fmt.Errorf("esiur: an encryption provider named %q is already registered", provider.Name())
	}
	w.encryption[provider.Name()] = provider
	w.encOrder = append(w.encOrder, provider.Name())
	return nil
}

// EncryptionProvider returns the provider registered under name.
func (w *Warehouse) EncryptionProvider(name string) security.EncryptionProvider {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.encryption[name]
}

// EncryptionProviderNames lists the registered encryption providers in registration order.
func (w *Warehouse) EncryptionProviderNames() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.encOrder...)
}

// ---- permissions --------------------------------------------------------------------------

// RegisterPermissions asks manager about every operation a peer attempts. Any denial wins.
func (w *Warehouse) RegisterPermissions(manager security.PermissionsManager) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.permissions = append(w.permissions, manager)
}

// Evaluate combines the managers' votes: a denial (or a manager that panics) wins, otherwise an
// allowance, otherwise security.DefaultPermissions.
func (w *Warehouse) Evaluate(r Resource, session *security.Session, action security.ActionType, member any, inquirer any) Evaluation {
	w.mu.Lock()
	managers := append([]security.PermissionsManager{}, w.permissions...)
	w.mu.Unlock()
	allowed, denied := false, false
	reason := ""
	var subject any
	if r != nil {
		subject = r
	}
	for _, m := range managers {
		ruling := func() (ruling security.Ruling) {
			defer func() {
				if p := recover(); p != nil {
					log.Printf("esiur: a permissions manager failed: %v", p)
					ruling = security.Denied
					if reason == "" {
						reason = "A permissions manager failed while evaluating the operation."
					}
				}
			}()
			return m.Applicable(subject, session, action, member, inquirer)
		}()
		switch ruling {
		case security.Denied:
			denied = true
			if reason == "" {
				reason = fmt.Sprintf("Permissions manager '%T' denied the operation.", m)
			}
		case security.Allowed:
			allowed = true
		}
	}
	verdict := security.DefaultPermissions(action)
	if denied {
		verdict = security.Denied
	} else if allowed {
		verdict = security.Allowed
	}
	if verdict == security.Allowed {
		return Evaluation{Allowed: true}
	}
	return Evaluation{Allowed: false, Reason: reason}
}

// ---- types --------------------------------------------------------------------------------

// HostedTypeOf is the definition peers are shown for the resource type t (a pointer to
// struct), created (and given the next type id) on first use.
func (w *Warehouse) HostedTypeOf(t reflect.Type) (*HostedType, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hostedTypeLocked(t)
}

func (w *Warehouse) hostedTypeLocked(t reflect.Type) (*HostedType, error) {
	if h, ok := w.typesByGo[t]; ok {
		return h, nil
	}
	id := w.typeCounter + 1
	h, err := describe(t, id, w.Registry, w.nameOfLocked(id, t.Elem().Name()))
	if err != nil {
		return nil, err
	}
	w.typeCounter = id
	w.typesByGo[t] = h
	w.typesByID[id] = h
	return h, nil
}

func (w *Warehouse) nameOfLocked(pendingID uint64, pendingName string) data.NameOf {
	return func(id uint64) (string, error) {
		if id == pendingID {
			return pendingName, nil
		}
		if h, ok := w.typesByID[id]; ok {
			return h.Name(), nil
		}
		if w.Registry != nil {
			return w.Registry.NameOf(id)
		}
		return "", fmt.Errorf("esiur: TypeDef %d is unknown", id)
	}
}

// TypeByID is the hosted definition with id.
func (w *Warehouse) TypeByID(id uint64) (*HostedType, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	h, ok := w.typesByID[id]
	return h, ok
}

// ---- resources ----------------------------------------------------------------------------

// GetByID is the hosted resource with this instance id.
func (w *Warehouse) GetByID(id uint32) Resource {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.resources[id]
}

// Stores lists the stores.
func (w *Warehouse) Stores() []Store {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]Store(nil), w.stores...)
}

// IsOpen reports whether Open ran.
func (w *Warehouse) IsOpen() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.opened
}

// Put hosts r at path and gives it its Instance. A path of one segment must be a Store; a longer
// one puts the resource into the store of its parent path.
func (w *Warehouse) Put(ctx context.Context, path string, r Resource) error {
	b := r.base()
	if b.Instance() != nil {
		return errors.New("esiur: the resource is already hosted")
	}
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return errors.New("esiur: invalid path")
	}
	location := strings.Split(strings.TrimLeft(path, "/"), "/")
	name := location[len(location)-1]
	var store Store
	if len(location) == 1 {
		s, ok := r.(Store)
		if !ok {
			return errors.New("esiur: a resource that is not a store cannot be put at the root")
		}
		store = s
	} else {
		parent, err := w.Query(ctx, strings.Join(location[:len(location)-1], "/"))
		if err != nil {
			return err
		}
		if parent == nil || InstanceOf(parent) == nil {
			return errors.New("esiur: can't find the parent resource")
		}
		store = InstanceOf(parent).Store
	}

	w.mu.Lock()
	hosted, err := w.hostedTypeLocked(reflect.TypeOf(r))
	if err != nil {
		w.mu.Unlock()
		return err
	}
	w.counter++
	id := w.counter
	w.mu.Unlock()

	instance := newInstance(w, id, name, r, store, hosted)
	b.mu.Lock()
	b.instance, b.self = instance, r
	b.mu.Unlock()
	instance.bind()
	b.OnDestroy(instance.onDestroy)

	if s, isStore := r.(Store); isStore && any(s) == any(store) {
		w.mu.Lock()
		w.stores = append(w.stores, s)
		w.mu.Unlock()
	} else if err := store.Put(ctx, r, strings.Join(location[1:], "/")); err != nil {
		instance.unbind()
		b.mu.Lock()
		b.instance = nil
		b.mu.Unlock()
		return fmt.Errorf("esiur: the store refused the resource: %w", err)
	}
	w.mu.Lock()
	w.resources[id] = r
	opened := w.opened
	w.mu.Unlock()
	if opened {
		if err := handle(ctx, r, OpInitialize); err != nil {
			return err
		}
		if _, isStore := r.(Store); isStore {
			return handle(ctx, r, OpOpen)
		}
	}
	return nil
}

// Query is the hosted resource at a link such as "sys/greeter", or nil.
func (w *Warehouse) Query(ctx context.Context, path string) (Resource, error) {
	parts := strings.Split(strings.Trim(strings.TrimSpace(path), "/"), "/")
	for _, s := range w.Stores() {
		i := InstanceOf(s)
		if i != nil && parts[0] == i.Name {
			if len(parts) == 1 {
				return s, nil
			}
			return s.Get(ctx, strings.Join(parts[1:], "/"))
		}
	}
	return nil, nil
}

// Remove stops hosting r: its store forgets it and it is destroyed, which detaches every peer.
func (w *Warehouse) Remove(ctx context.Context, r Resource) (bool, error) {
	i := InstanceOf(r)
	if i == nil {
		return false, nil
	}
	w.mu.Lock()
	delete(w.resources, i.ID)
	for k, s := range w.stores {
		if any(s) == any(r) {
			w.stores = append(w.stores[:k], w.stores[k+1:]...)
			break
		}
	}
	w.mu.Unlock()
	if any(i.Store) != any(r) {
		if _, err := i.Store.Remove(ctx, r); err != nil {
			return false, err
		}
	}
	r.base().Destroy()
	i.unbind()
	b := r.base()
	b.mu.Lock()
	b.instance = nil
	b.mu.Unlock()
	return true, nil
}

// Open initializes every resource and opens every store. Resources put afterwards are
// initialized as they arrive.
func (w *Warehouse) Open(ctx context.Context) error {
	w.mu.Lock()
	w.opened = true
	resources := make([]Resource, 0, len(w.resources))
	for id := uint32(1); id <= w.counter; id++ {
		if r, ok := w.resources[id]; ok {
			resources = append(resources, r)
		}
	}
	stores := append([]Store(nil), w.stores...)
	w.mu.Unlock()
	for _, r := range resources {
		if err := handle(ctx, r, OpInitialize); err != nil {
			return err
		}
	}
	for _, s := range stores {
		if err := handle(ctx, s, OpOpen); err != nil {
			return err
		}
	}
	return nil
}

// Close terminates every resource in two phases (OpTerminate, then OpSystemTerminated). Every
// resource is told even if some fail; the failures are returned joined.
func (w *Warehouse) Close(ctx context.Context) error {
	w.mu.Lock()
	var resources []Resource
	for id := uint32(1); id <= w.counter; id++ {
		if r, ok := w.resources[id]; ok {
			resources = append(resources, r)
		}
	}
	w.mu.Unlock()
	var errs []error
	for _, op := range []Operation{OpTerminate, OpSystemTerminated} {
		for _, r := range resources {
			if err := handle(ctx, r, op); err != nil {
				errs = append(errs, err)
			}
		}
	}
	w.mu.Lock()
	w.opened = false
	w.mu.Unlock()
	return errors.Join(errs...)
}
