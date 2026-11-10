package resource

import (
	"crypto/rand"
	"fmt"
	"log"
	"reflect"
	"sync"
	"time"

	"github.com/esiur/esiur-go/data"
)

// PropertyModified describes one property change.
type PropertyModified struct {
	Resource   Resource
	Index      int
	Value      any
	Age        uint64
	Cursor     Cursor
	RecordedAt time.Time
}

// EventOccurred describes one raised event.
type EventOccurred struct {
	Resource   Resource
	Index      int
	Value      any
	Cursor     Cursor
	RecordedAt time.Time
}

// Instance is what a warehouse knows about one resource: its id, name and store, its type, and
// the ordered stream of changes it has made. Every property change and every raised event takes
// the next revision of the stream; a peer compares revisions to drop what it has seen.
type Instance struct {
	Warehouse *Warehouse
	ID        uint32
	Name      string
	Resource  Resource
	Store     Store
	Type      *HostedType

	mu                sync.Mutex
	variables         map[string]any
	destroyed         bool
	cursor            Cursor
	ages              []uint64
	dates             []time.Time
	propertyListeners []*func(PropertyModified)
	eventListeners    []*func(EventOccurred)
	destroyListeners  []*func(Resource)
}

func newInstance(w *Warehouse, id uint32, name string, r Resource, store Store, hosted *HostedType) *Instance {
	i := &Instance{
		Warehouse: w, ID: id, Name: name, Resource: r, Store: store, Type: hosted,
		variables: map[string]any{},
		ages:      make([]uint64, len(hosted.Properties)),
		dates:     make([]time.Time, len(hosted.Properties)),
	}
	if _, err := rand.Read(i.cursor.Generation[:]); err != nil {
		panic(err)
	}
	return i
}

func (i *Instance) String() string {
	return fmt.Sprintf("<Instance #%d %q %s>", i.ID, i.Link(), i.Type.Name())
}

// Variable reads free-form per-resource state kept by stores and managers.
func (i *Instance) Variable(name string) (any, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	v, ok := i.variables[name]
	return v, ok
}

// SetVariable writes free-form per-resource state.
func (i *Instance) SetVariable(name string, value any) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.variables[name] = value
}

// IsDestroyed reports whether the resource was destroyed.
func (i *Instance) IsDestroyed() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.destroyed
}

// Link is the path a peer resolves to reach this resource, such as "sys/greeter".
func (i *Instance) Link() string {
	if any(i.Resource) == any(i.Store) {
		return i.Name // a store's link is its own name
	}
	storeName := ""
	if si := InstanceOf(i.Store); si != nil {
		storeName = si.Name
	}
	return storeName + "/" + i.Store.Link(i.Resource)
}

// Cursor is the position of the latest change.
func (i *Instance) Cursor() Cursor {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.cursor
}

// AgeOf is the revision at which property index last changed (0 if it never has).
func (i *Instance) AgeOf(index int) uint64 {
	i.mu.Lock()
	defer i.mu.Unlock()
	if index < 0 || index >= len(i.ages) {
		return 0
	}
	return i.ages[index]
}

var epoch = time.Unix(0, 0).UTC()

// ModifiedAt is when property index last changed; the Unix epoch if it never has.
func (i *Instance) ModifiedAt(index int) time.Time {
	i.mu.Lock()
	defer i.mu.Unlock()
	if index < 0 || index >= len(i.dates) || i.dates[index].IsZero() {
		return epoch
	}
	return i.dates[index]
}

func (i *Instance) field(f []int) reflect.Value {
	return reflect.ValueOf(i.Resource).Elem().FieldByIndex(f)
}

// ValueOf is the current value of property index.
func (i *Instance) ValueOf(index int) any {
	return i.field(i.Type.Properties[index].field).Addr().Interface().(propertyField).getAny()
}

// SetValue converts value to the property's Go type and sets it (notifying peers).
func (i *Instance) SetValue(index int, value any) error {
	p := i.Type.Properties[index]
	v, err := data.Convert(value, p.Type)
	if err != nil {
		return err
	}
	i.field(p.field).Addr().Interface().(propertyField).setAny(v)
	return nil
}

func (i *Instance) bind() {
	for index, p := range i.Type.Properties {
		i.field(p.field).Addr().Interface().(propertyField).bind(i, index)
	}
	for index, e := range i.Type.Events {
		i.field(e.field).Addr().Interface().(eventField).bind(i, index)
	}
}

func (i *Instance) unbind() {
	for _, p := range i.Type.Properties {
		i.field(p.field).Addr().Interface().(propertyField).bind(nil, 0)
	}
	for _, e := range i.Type.Events {
		i.field(e.field).Addr().Interface().(eventField).bind(nil, 0)
	}
}

func (i *Instance) nextCursorLocked() Cursor {
	i.cursor.Revision++
	return i.cursor
}

func (i *Instance) modified(index int, value any) {
	i.mu.Lock()
	cursor := i.nextCursorLocked()
	now := time.Now().UTC()
	if index < len(i.ages) {
		i.ages[index] = cursor.Revision
		i.dates[index] = now
	}
	listeners := append([]*func(PropertyModified){}, i.propertyListeners...)
	i.mu.Unlock()
	i.Store.Modify(i.Resource, index, value, cursor.Revision, now)
	change := PropertyModified{i.Resource, index, value, cursor.Revision, cursor, now}
	for _, l := range listeners {
		safely(func() { (*l)(change) })
	}
}

func (i *Instance) eventOccurred(index int, value any) {
	i.mu.Lock()
	cursor := i.nextCursorLocked()
	listeners := append([]*func(EventOccurred){}, i.eventListeners...)
	i.mu.Unlock()
	occurrence := EventOccurred{i.Resource, index, value, cursor, time.Now().UTC()}
	for _, l := range listeners {
		safely(func() { (*l)(occurrence) })
	}
}

func safely(f func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("esiur: a resource change listener failed: %v", r)
		}
	}()
	f()
}

func addListener[T any](mu *sync.Mutex, list *[]*func(T), f func(T)) func() {
	mu.Lock()
	defer mu.Unlock()
	p := &f
	*list = append(*list, p)
	return func() {
		mu.Lock()
		defer mu.Unlock()
		for k, l := range *list {
			if l == p {
				*list = append((*list)[:k], (*list)[k+1:]...)
				return
			}
		}
	}
}

// OnPropertyModified registers a listener of property changes; the returned function removes it.
func (i *Instance) OnPropertyModified(f func(PropertyModified)) func() {
	return addListener(&i.mu, &i.propertyListeners, f)
}

// OnEventOccurred registers a listener of raised events; the returned function removes it.
func (i *Instance) OnEventOccurred(f func(EventOccurred)) func() {
	return addListener(&i.mu, &i.eventListeners, f)
}

// OnDestroyed registers a listener of the resource's destruction.
func (i *Instance) OnDestroyed(f func(Resource)) func() {
	return addListener(&i.mu, &i.destroyListeners, f)
}

func (i *Instance) onDestroy(r Resource) {
	i.mu.Lock()
	i.destroyed = true
	listeners := append([]*func(Resource){}, i.destroyListeners...)
	i.mu.Unlock()
	for _, l := range listeners {
		safely(func() { (*l)(r) })
	}
}
