package resource

import (
	"context"
	"log"
	"reflect"
	"sync"

	"github.com/esiur/esiur-go/data"
)

// Operation is a lifecycle step the Warehouse hands to a resource (same values as esiur-dotnet).
type Operation uint8

const (
	OpOpen              Operation = 0
	OpInitialize        Operation = 1
	OpConfigure         Operation = 2
	OpClose             Operation = 3
	OpTerminate         Operation = 4
	OpSystemReady       Operation = 5
	OpSystemReloading   Operation = 6
	OpSystemReloaded    Operation = 7
	OpSystemTerminating Operation = 8
	// OpSystemTerminated is the second termination phase; it shares OpSystemTerminating's
	// value, as in dotnet.
	OpSystemTerminated Operation = 8
	OpSave             Operation = 9
	OpLoad             Operation = 10
	OpPause            Operation = 11
	OpResume           Operation = 12
)

// Resource is an object a Warehouse hosts. Implement it by embedding Base in a struct and put a
// pointer to the struct into a warehouse:
//
//	type Greeter struct {
//		resource.Base
//		Visits resource.Property[int32]
//		Label  resource.Property[string] `esiur:"label,readonly"`
//		Ping   resource.Event[string]
//		Tick   resource.Event[string] `esiur:",auto"`
//	}
//
//	func (g *Greeter) Greet(name string) string { ... }
//
// Exported Property and Event fields are the resource's properties and events, in declaration
// order (embedded structs first); exported methods are its functions, in name order. Members
// are exported under their Go name with a lower-case first word ("Greet" -> "greet") unless an
// `esiur:"name"` tag says otherwise. A method may take a context.Context first and may return a
// value, an error, or both.
type Resource interface {
	base() *Base
}

// Creator is implemented by a resource that sets itself up once it is in a warehouse.
type Creator interface {
	Create() error
}

// OperationHandler is implemented by a resource that reacts to lifecycle steps itself (then
// Create is not called for it).
type OperationHandler interface {
	Handle(ctx context.Context, op Operation) error
}

// Base is embedded in every hosted resource.
type Base struct {
	mu        sync.Mutex
	instance  *Instance
	self      Resource
	onDestroy []*func(Resource)
}

func (b *Base) base() *Base { return b }

// Instance is the resource's identity and change stream; nil until it is put in a warehouse.
func (b *Base) Instance() *Instance {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.instance
}

// OnDestroy registers handler, called when the resource is destroyed; the returned function
// removes it.
func (b *Base) OnDestroy(handler func(Resource)) (remove func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := &handler
	b.onDestroy = append(b.onDestroy, p)
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		for i, h := range b.onDestroy {
			if h == p {
				b.onDestroy = append(b.onDestroy[:i], b.onDestroy[i+1:]...)
				return
			}
		}
	}
}

// Destroy tells everything watching this resource that it is gone.
func (b *Base) Destroy() {
	b.mu.Lock()
	handlers := append([]*func(Resource){}, b.onDestroy...)
	self := b.self
	b.mu.Unlock()
	for _, h := range handlers {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("esiur: a destroy handler failed: %v", r)
				}
			}()
			(*h)(self)
		}()
	}
}

func handle(ctx context.Context, r Resource, op Operation) error {
	if h, ok := r.(OperationHandler); ok {
		return h.Handle(ctx, op)
	}
	if c, ok := r.(Creator); ok && op == OpInitialize {
		return c.Create()
	}
	return nil
}

// InstanceOf is the instance of r (nil if it is not hosted).
func InstanceOf(r Resource) *Instance { return r.base().Instance() }

func init() {
	data.RegisterResourceInterface(reflect.TypeOf((*Resource)(nil)).Elem())
}
