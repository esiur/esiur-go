package resource

import (
	"log"
	"reflect"
	"sync"
)

// Property is a property that tells its resource's Instance when it changes, so attached peers
// are notified. Read it with Get and change it with Set.
type Property[T any] struct {
	mu       sync.RWMutex
	value    T
	instance *Instance
	index    int
}

// Get returns the current value.
func (p *Property[T]) Get() T {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.value
}

// Set changes the value and notifies the peers attached to the resource.
func (p *Property[T]) Set(value T) {
	p.mu.Lock()
	p.value = value
	instance, index := p.instance, p.index
	p.mu.Unlock()
	if instance != nil {
		instance.modified(index, value)
	}
}

// Init sets the value without notifying anyone (for initial values).
func (p *Property[T]) Init(value T) {
	p.mu.Lock()
	p.value = value
	p.mu.Unlock()
}

func (p *Property[T]) bind(instance *Instance, index int) {
	p.mu.Lock()
	p.instance, p.index = instance, index
	p.mu.Unlock()
}

func (p *Property[T]) getAny() any { return p.Get() }

func (p *Property[T]) setAny(v reflect.Value) {
	var value T
	if v.IsValid() {
		if x, ok := v.Interface().(T); ok {
			value = x
		}
	}
	p.Set(value)
}

func (p *Property[T]) valueType() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }

type propertyField interface {
	bind(*Instance, int)
	getAny() any
	setAny(reflect.Value)
	valueType() reflect.Type
}

// Event is an exported event. Raise it with Emit.
type Event[T any] struct {
	mu        sync.Mutex
	instance  *Instance
	index     int
	listeners []*func(T)
}

// Emit raises the event: local listeners run, then attached peers that want it are told.
func (e *Event[T]) Emit(value T) {
	e.mu.Lock()
	listeners := append([]*func(T){}, e.listeners...)
	instance, index := e.instance, e.index
	e.mu.Unlock()
	for _, l := range listeners {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("esiur: an event listener failed: %v", r)
				}
			}()
			(*l)(value)
		}()
	}
	if instance != nil {
		instance.eventOccurred(index, value)
	}
}

// Listen calls listener whenever the event is raised in this process; the returned function
// removes it.
func (e *Event[T]) Listen(listener func(T)) (remove func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := &listener
	e.listeners = append(e.listeners, p)
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for i, l := range e.listeners {
			if l == p {
				e.listeners = append(e.listeners[:i], e.listeners[i+1:]...)
				return
			}
		}
	}
}

func (e *Event[T]) bind(instance *Instance, index int) {
	e.mu.Lock()
	e.instance, e.index = instance, index
	e.mu.Unlock()
}

func (e *Event[T]) valueType() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }

type eventField interface {
	bind(*Instance, int)
	valueType() reflect.Type
}

var (
	propertyFieldType = reflect.TypeOf((*propertyField)(nil)).Elem()
	eventFieldType    = reflect.TypeOf((*eventField)(nil)).Elem()
)
