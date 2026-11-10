package ep

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"sync"
	"time"

	"github.com/esiur/esiur-go/core"
	"github.com/esiur/esiur-go/data"
	"github.com/esiur/esiur-go/packet"
	"github.com/esiur/esiur-go/resource"
)

func init() {
	data.RegisterResourceInterface(reflect.TypeOf(&RemoteResource{}))
}

// RemoteResource is the local stand-in for a resource hosted by a peer. It keeps the last value
// of every property (refreshed by the peer's notifications), turns calls into requests, and
// delivers the peer's events to listeners. Members are found by name, ignoring case and
// underscores.
type RemoteResource struct {
	conn       *Connection
	instanceID uint32
	typeDef    *resource.TypeDef
	// typeID is the id the peer reported for the resource's type (0 when it relays it).
	typeID uint64
	link   string
	hops   int

	mu                sync.Mutex
	cursor            resource.Cursor
	values            map[int]any
	ages              map[int]uint64
	dates             map[int]time.Time
	propertyCursors   map[int]resource.Cursor
	eventCursors      map[int]resource.Cursor
	propertyListeners map[int][]*func(any)
	eventListeners    map[int][]*func(any)
	subscribed        map[int]bool
	subscriptionLocks map[int]*sync.Mutex
}

func newRemoteResource(c *Connection, id uint32, td *resource.TypeDef, typeID uint64, cursor resource.Cursor, link string, hops int) *RemoteResource {
	return &RemoteResource{
		conn: c, instanceID: id, typeDef: td, typeID: typeID, cursor: cursor, link: link, hops: hops,
		values: map[int]any{}, ages: map[int]uint64{}, dates: map[int]time.Time{},
		propertyCursors: map[int]resource.Cursor{}, eventCursors: map[int]resource.Cursor{},
		propertyListeners: map[int][]*func(any){}, eventListeners: map[int][]*func(any){},
		subscribed: map[int]bool{}, subscriptionLocks: map[int]*sync.Mutex{},
	}
}

func (r *RemoteResource) String() string {
	return fmt.Sprintf("<RemoteResource %s #%d %q>", r.typeDef.Name(), r.instanceID, r.link)
}

func (r *RemoteResource) Connection() *Connection    { return r.conn }
func (r *RemoteResource) InstanceID() uint32         { return r.instanceID }
func (r *RemoteResource) TypeDef() *resource.TypeDef { return r.typeDef }
func (r *RemoteResource) TypeID() uint64             { return r.typeID }
func (r *RemoteResource) Link() string               { return r.link }
func (r *RemoteResource) Hops() int                  { return r.hops }
func (r *RemoteResource) Cursor() resource.Cursor    { r.mu.Lock(); defer r.mu.Unlock(); return r.cursor }

func (r *RemoteResource) property(name string) (*data.PropertyDefInfo, error) {
	p, err := r.typeDef.FindProperty(name)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("esiur: %s has no property %q", r.typeDef.Name(), name)
	}
	return p, nil
}

// Get is the last known value of a property.
func (r *RemoteResource) Get(name string) (any, error) {
	p, err := r.property(name)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.values[p.Index], nil
}

// Value is Get that returns nil for an unknown property.
func (r *RemoteResource) Value(name string) any {
	v, _ := r.Get(name)
	return v
}

// Age is the revision at which a property last changed.
func (r *RemoteResource) Age(name string) uint64 {
	p, err := r.property(name)
	if err != nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ages[p.Index]
}

// ModifiedAt is when a property last changed, as the peer reported it.
func (r *RemoteResource) ModifiedAt(name string) time.Time {
	p, err := r.property(name)
	if err != nil {
		return time.Time{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dates[p.Index]
}

// Invoke calls an exported function of the resource.
func (r *RemoteResource) Invoke(ctx context.Context, name string, args ...any) (any, error) {
	f, err := r.typeDef.FindFunction(name)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, fmt.Errorf("esiur: %s has no function %q", r.typeDef.Name(), name)
	}
	if f.StreamMode != data.StreamNone {
		return nil, core.ManagementError(core.NotImplemented, "Streaming functions are not supported yet.")
	}
	if resource.IsStatic(f) {
		typeID := r.typeID
		if typeID == 0 {
			typeID = r.typeDef.ID()
		}
		return r.conn.StaticCall(ctx, typeID, f.Index, args...)
	}
	return r.conn.Invoke(ctx, r.instanceID, f.Index, args...)
}

// Set writes a property on the peer; the cached value follows once it accepts.
func (r *RemoteResource) Set(ctx context.Context, name string, value any) error {
	p, err := r.property(name)
	if err != nil {
		return err
	}
	if resource.IsReadOnly(p) {
		return core.ManagementError(core.ReadOnlyProperty, "'%s' is read-only.", p.Name)
	}
	if err := r.conn.SetProperty(ctx, r.instanceID, p.Index, value); err != nil {
		return err
	}
	r.mu.Lock()
	r.values[p.Index] = value
	r.mu.Unlock()
	return nil
}

// Detach stops receiving this resource's notifications.
func (r *RemoteResource) Detach(ctx context.Context) error {
	return r.conn.Detach(ctx, r.instanceID)
}

func removeListener(list *[]*func(any), p *func(any)) {
	for i, l := range *list {
		if l == p {
			*list = append((*list)[:i], (*list)[i+1:]...)
			return
		}
	}
}

// OnProperty calls listener(value) whenever the peer changes a property; the returned function
// removes it.
func (r *RemoteResource) OnProperty(name string, listener func(any)) (func(), error) {
	p, err := r.property(name)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ptr := &listener
	r.propertyListeners[p.Index] = append(r.propertyListeners[p.Index], ptr)
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		list := r.propertyListeners[p.Index]
		removeListener(&list, ptr)
		r.propertyListeners[p.Index] = list
	}, nil
}

// OnEvent calls listener(value) whenever the peer raises an event. The first listener of an
// event that needs it subscribes on the peer; this returns once that has happened. The returned
// function removes the listener, unsubscribing after the last one.
func (r *RemoteResource) OnEvent(ctx context.Context, name string, listener func(any)) (func(context.Context) error, error) {
	e, err := r.typeDef.FindEvent(name)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, fmt.Errorf("esiur: %s has no event %q", r.typeDef.Name(), name)
	}
	ptr := &listener
	r.mu.Lock()
	r.eventListeners[e.Index] = append(r.eventListeners[e.Index], ptr)
	r.mu.Unlock()
	remove := func() {
		r.mu.Lock()
		list := r.eventListeners[e.Index]
		removeListener(&list, ptr)
		r.eventListeners[e.Index] = list
		r.mu.Unlock()
	}
	if err := r.reconcile(ctx, e.Index); err != nil {
		remove()
		return nil, err
	}
	return func(ctx context.Context) error {
		remove()
		return r.reconcile(ctx, e.Index)
	}, nil
}

// reconcile brings the peer's subscription for event index in line with the listeners. The
// peer rejects a redundant subscribe or unsubscribe, so the state is tracked here.
func (r *RemoteResource) reconcile(ctx context.Context, index int) error {
	e := r.typeDef.EventAt(index)
	if e == nil || !(resource.IsSubscribable(e) || resource.IsHistorical(e)) {
		return nil
	}
	r.mu.Lock()
	lock := r.subscriptionLocks[index]
	if lock == nil {
		lock = &sync.Mutex{}
		r.subscriptionLocks[index] = lock
	}
	r.mu.Unlock()
	lock.Lock()
	defer lock.Unlock()
	r.mu.Lock()
	wanted := len(r.eventListeners[index]) > 0
	subscribed := r.subscribed[index]
	after, ok := r.eventCursors[index]
	if !ok {
		after = r.cursor
	}
	r.mu.Unlock()
	switch {
	case wanted && !subscribed:
		if _, err := r.conn.Subscribe(ctx, r.instanceID, index, after); err != nil {
			return err
		}
		r.mu.Lock()
		r.subscribed[index] = true
		r.mu.Unlock()
	case !wanted && subscribed:
		if err := r.conn.Unsubscribe(ctx, r.instanceID, index); err != nil {
			return err
		}
		r.mu.Lock()
		delete(r.subscribed, index)
		r.mu.Unlock()
	}
	return nil
}

// ---- fed by the connection ----------------------------------------------------------------

// setSnapshot seeds a value from an attach reply: it is state, not a change.
func (r *RemoteResource) setSnapshot(index int, age uint64, date time.Time, value any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[index] = value
	r.ages[index] = age
	r.dates[index] = date
	if !r.cursor.IsEmpty() {
		r.propertyCursors[index] = resource.Cursor{Generation: r.cursor.Generation, Revision: age}
	}
	if age > r.cursor.Revision {
		r.cursor.Revision = age
	}
}

func isStale(previous resource.Cursor, had bool, cursor resource.Cursor) bool {
	return had && previous.Generation == cursor.Generation && previous.Revision >= cursor.Revision
}

func (r *RemoteResource) observeLocked(cursor resource.Cursor) {
	if r.cursor.IsEmpty() || r.cursor.Generation != cursor.Generation || cursor.Revision > r.cursor.Revision {
		r.cursor = cursor
	}
}

func (r *RemoteResource) updateProperty(index int, value any, cursor resource.Cursor, date time.Time) {
	r.mu.Lock()
	previous, had := r.propertyCursors[index]
	if isStale(previous, had, cursor) {
		r.mu.Unlock()
		return
	}
	r.propertyCursors[index] = cursor
	r.observeLocked(cursor)
	r.values[index] = value
	r.ages[index] = cursor.Revision
	if date.IsZero() {
		date = time.Now().UTC()
	}
	r.dates[index] = date
	listeners := append([]*func(any){}, r.propertyListeners[index]...)
	r.mu.Unlock()
	for _, l := range listeners {
		f := *l
		r.conn.callbacks.post(func() { f(value) })
	}
}

func (r *RemoteResource) applyEvent(index int, value any, cursor resource.Cursor) {
	r.mu.Lock()
	previous, had := r.eventCursors[index]
	if isStale(previous, had, cursor) {
		r.mu.Unlock()
		return
	}
	r.eventCursors[index] = cursor
	r.observeLocked(cursor)
	listeners := append([]*func(any){}, r.eventListeners[index]...)
	r.mu.Unlock()
	for _, l := range listeners {
		f := *l
		r.conn.callbacks.post(func() { f(value) })
	}
}

// ---- remote resources on the connection ---------------------------------------------------

// composeResource is how a resource object is written to this peer. A proxy this connection
// attached is the peer's own resource (a local reference from the receiver's view); a resource
// of this node's warehouse is one the peer attaches to (a remote reference).
func (c *Connection) composeResource(value any) (data.ResourceID, bool) {
	switch v := value.(type) {
	case *RemoteResource:
		if v != nil && v.conn == c {
			return data.ResourceID{Local: true, ID: v.instanceID}, true
		}
		return data.ResourceID{}, false
	case resource.Resource:
		i := resource.InstanceOf(v)
		if c.warehouse == nil || i == nil || i.Warehouse != c.warehouse {
			return data.ResourceID{}, false
		}
		return data.ResourceID{Local: false, ID: i.ID}, true
	}
	return data.ResourceID{}, false
}

// Get resolves a resource link on the peer ("sys/greeter") and attaches to it.
func (c *Connection) Get(ctx context.Context, link string) (*RemoteResource, error) {
	id, err := c.ResourceID(ctx, link)
	if err != nil {
		return nil, err
	}
	return c.Attach(ctx, id)
}

// ResourceID is the instance id of the resource at link.
func (c *Connection) ResourceID(ctx context.Context, link string) (uint32, error) {
	found, err := c.RequestWith(ctx, packet.GetResourceIDByLink, RequestOptions{KeepReferences: true}, link)
	if err != nil {
		return 0, err
	}
	if r, ok := found.(data.ResourceID); ok {
		return r.ID, nil
	}
	if _, isBool := found.(bool); !isBool {
		if i, ok := data.ToInt64(found); ok {
			return uint32(i), nil
		}
	}
	return 0, malformed("GetResourceIdByLink did not return a resource id.")
}

// Attach attaches to the peer's resource id: fetch its type and current property values, and
// start receiving its notifications. Attaching again returns the same proxy.
func (c *Connection) Attach(ctx context.Context, id uint32) (*RemoteResource, error) {
	c.mu.Lock()
	if existing := c.attached[id]; existing != nil {
		c.mu.Unlock()
		return existing, nil
	}
	if call := c.attaching[id]; call != nil {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.resource, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &attachCall{done: make(chan struct{})}
	c.attaching[id] = call
	c.mu.Unlock()

	call.resource, call.err = c.attach(ctx, id)
	c.mu.Lock()
	delete(c.attaching, id)
	delete(c.needed, id)
	c.mu.Unlock()
	close(call.done)
	return call.resource, call.err
}

func (c *Connection) attach(ctx context.Context, id uint32) (*RemoteResource, error) {
	result, err := c.RequestWith(ctx, packet.AttachResource, RequestOptions{KeepReferences: true}, int64(id))
	if err != nil {
		return nil, err
	}
	// [type id, generation, revision, link, hops, property values]
	reply := asList(result)
	if len(reply) < 5 {
		return nil, malformed("AttachResource did not return the resource's description.")
	}
	typeID, err := asInt(reply[0])
	if err != nil {
		return nil, err
	}
	cursor, err := resource.CursorFromWire(reply[1], reply[2])
	if err != nil {
		return nil, malformed("%v", err)
	}
	td, err := c.typeDefOf(ctx, id, uint64(typeID))
	if err != nil {
		return nil, err
	}
	link, _ := reply[3].(string)
	hops, _ := data.ToInt64(reply[4])
	reportedType := td.ID()
	if reportedType == 0 {
		reportedType = uint64(typeID)
	}
	r := newRemoteResource(c, id, td, reportedType, cursor, link, int(hops))
	// Published before its values are decoded, so a value that refers back to this resource
	// resolves to it instead of waiting for an attach that is waiting on it.
	c.mu.Lock()
	c.needed[id] = r
	c.mu.Unlock()
	if len(reply) > 5 {
		if raw, ok := reply[5].([]byte); ok {
			if err := c.applySnapshot(ctx, r, raw); err != nil {
				return nil, err
			}
		}
	}
	c.mu.Lock()
	c.attached[id] = r
	c.mu.Unlock()
	return r, nil
}

// applySnapshot reads the (age, date, value) triples, one per property in definition order.
func (c *Connection) applySnapshot(ctx context.Context, r *RemoteResource, raw []byte) error {
	parser := c.Parser()
	offset := 0
	for _, p := range r.typeDef.Properties {
		var parts [3]any
		for k := range parts {
			v, used, err := parser.ParseAt(raw, offset)
			if err != nil {
				return decodeFailure(err)
			}
			parts[k] = v
			offset += used
		}
		age, _ := data.ToInt64(parts[0])
		date, _ := parts[1].(time.Time)
		value, err := c.resolveValue(ctx, parts[2])
		if err != nil {
			return err
		}
		r.setSnapshot(p.Index, uint64(age), date, value)
	}
	return nil
}

// typeDefOf is the definition of an attached resource's type: by the id the peer reported, and
// through the resource itself when the peer does not serve the type by id.
func (c *Connection) typeDefOf(ctx context.Context, instanceID uint32, typeID uint64) (*resource.TypeDef, error) {
	if typeID != 0 {
		if td, err := c.FetchTypeDef(ctx, typeID); err == nil {
			return td, nil
		}
	}
	return c.FetchTypeDefByResourceID(ctx, instanceID)
}

// FetchTypeDef is a type's definition by the id the peer knows it by.
func (c *Connection) FetchTypeDef(ctx context.Context, typeID uint64) (*resource.TypeDef, error) {
	c.mu.Lock()
	known := c.typedefs[typeID]
	c.mu.Unlock()
	if known != nil {
		return known, nil
	}
	info, err := c.Request(ctx, packet.TypeDefByID, typeID)
	if err != nil {
		return nil, err
	}
	return c.rememberTypeDef(info, typeID)
}

// FetchTypeDefByResourceID is the definition of the type of the peer's resource instanceID.
func (c *Connection) FetchTypeDefByResourceID(ctx context.Context, instanceID uint32) (*resource.TypeDef, error) {
	info, err := c.Request(ctx, packet.TypeDefByResourceID, int64(instanceID))
	if err != nil {
		return nil, err
	}
	return c.rememberTypeDef(info, 0)
}

func (c *Connection) rememberTypeDef(info any, requested uint64) (*resource.TypeDef, error) {
	if raw, ok := info.([]byte); ok {
		// esiur-ts sends the definition as raw data holding a complete TypeDef TDU.
		v, err := c.Parser().Parse(raw)
		if err != nil {
			return nil, decodeFailure(err)
		}
		info = v
	}
	ti, ok := info.(*data.TypeDefInfo)
	if !ok {
		return nil, malformed("The peer did not return a TypeDef.")
	}
	td := resource.NewTypeDef(ti)
	c.mu.Lock()
	if ti.ID != 0 {
		c.typedefs[ti.ID] = td
	} else if requested != 0 {
		c.typedefs[requested] = td
	}
	c.mu.Unlock()
	return td, nil
}

// Invoke calls function index of the peer's resource instanceID.
func (c *Connection) Invoke(ctx context.Context, instanceID uint32, index int, args ...any) (any, error) {
	return c.Request(ctx, packet.InvokeFunction, int64(instanceID), uint8(index), argsList(args))
}

// StaticCall calls static function index of the peer's type typeID.
func (c *Connection) StaticCall(ctx context.Context, typeID uint64, index int, args ...any) (any, error) {
	return c.Request(ctx, packet.StaticCall, typeID, uint8(index), argsList(args))
}

func argsList(args []any) []any {
	if args == nil {
		return []any{}
	}
	return args
}

// SetProperty writes property index of the peer's resource instanceID.
func (c *Connection) SetProperty(ctx context.Context, instanceID uint32, index int, value any) error {
	_, err := c.Request(ctx, packet.SetProperty, int64(instanceID), uint8(index), value)
	return err
}

// Subscribe asks the peer to push event index of resource instanceID. Occurrences it replays
// arrive before this returns.
func (c *Connection) Subscribe(ctx context.Context, instanceID uint32, index int, after resource.Cursor) (resource.Cursor, error) {
	result, err := c.Request(ctx, packet.Subscribe, int64(instanceID), uint8(index), after.Generation[:], after.Revision)
	if err != nil {
		return resource.Cursor{}, err
	}
	c.mu.Lock()
	tail := c.notifyTail
	c.mu.Unlock()
	if tail != nil {
		select {
		case <-tail:
		case <-ctx.Done():
			return resource.Cursor{}, ctx.Err()
		}
	}
	values := asList(result)
	if len(values) < 2 {
		return resource.Cursor{}, malformed("Subscribe did not return a cursor.")
	}
	cursor, err := resource.CursorFromWire(values[0], values[1])
	if err != nil {
		return resource.Cursor{}, malformed("%v", err)
	}
	return cursor, nil
}

// Unsubscribe stops the peer pushing event index of resource instanceID.
func (c *Connection) Unsubscribe(ctx context.Context, instanceID uint32, index int) error {
	_, err := c.Request(ctx, packet.Unsubscribe, int64(instanceID), uint8(index))
	return err
}

// Detach stops receiving a resource's notifications; it keeps living for other peers.
func (c *Connection) Detach(ctx context.Context, instanceID uint32) error {
	if _, err := c.Request(ctx, packet.DetachResource, int64(instanceID)); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.attached, instanceID)
	c.mu.Unlock()
	return nil
}

// resolveValue replaces the peer's resource references in a decoded value with attached
// proxies.
func (c *Connection) resolveValue(ctx context.Context, value any) (any, error) {
	if !hasRemoteReference(value) {
		return value, nil
	}
	switch v := value.(type) {
	case data.ResourceID:
		if v.Local {
			return v, nil
		}
		return c.resolveResource(ctx, v.ID)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			r, err := c.resolveValue(ctx, item)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case data.Map:
		out := make(data.Map, len(v))
		for i, e := range v {
			k, err := c.resolveValue(ctx, e.Key)
			if err != nil {
				return nil, err
			}
			val, err := c.resolveValue(ctx, e.Value)
			if err != nil {
				return nil, err
			}
			out[i] = data.MapEntry{Key: k, Value: val}
		}
		return out, nil
	case data.TypedTuple:
		values, err := c.resolveValue(ctx, v.Values)
		if err != nil {
			return nil, err
		}
		return data.TypedTuple{Types: v.Types, Values: values.([]any)}, nil
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Map {
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		for _, k := range rv.MapKeys() {
			r, err := c.resolveValue(ctx, rv.MapIndex(k).Interface())
			if err != nil {
				return nil, err
			}
			if r == nil {
				out.SetMapIndex(k, reflect.Zero(rv.Type().Elem()))
			} else {
				out.SetMapIndex(k, reflect.ValueOf(r))
			}
		}
		return out.Interface(), nil
	}
	return value, nil
}

func (c *Connection) resolveResource(ctx context.Context, id uint32) (*RemoteResource, error) {
	c.mu.Lock()
	r := c.attached[id]
	if r == nil {
		r = c.needed[id]
	}
	c.mu.Unlock()
	if r != nil {
		return r, nil
	}
	return c.Attach(ctx, id)
}

// resourceNotification handles PropertyModified and EventOccurred. Values that refer to
// resources are attached first, and nothing overtakes a notification still waiting for that,
// so listeners see changes in the order the peer made them.
func (c *Connection) resourceNotification(action uint8, tdu *data.ParsedTdu) error {
	values, err := c.Decode(tdu)
	if err != nil {
		return err
	}
	c.mu.Lock()
	previous := c.notifyTail
	idle := previous == nil
	if !idle {
		select {
		case <-previous:
			idle = true
		default:
		}
	}
	if idle && !hasRemoteReference(values) {
		c.notifyTail = nil
		c.mu.Unlock()
		c.applyNotification(action, values)
		return nil
	}
	done := make(chan struct{})
	c.notifyTail = done
	c.mu.Unlock()
	go func() {
		defer close(done)
		if previous != nil {
			<-previous
		}
		resolved, err := c.resolveValue(context.Background(), values)
		if err != nil {
			log.Printf("esiur: closing a connection after a failed notification: %v", err)
			c.Close()
			return
		}
		c.applyNotification(action, resolved)
	}()
	return nil
}

func (c *Connection) applyNotification(action uint8, value any) {
	// [instance id, generation, revision, date, member index, value]
	values := asList(value)
	fail := func(err error) {
		log.Printf("esiur: closing a connection after a malformed notification: %v", err)
		c.Close()
	}
	if len(values) < 6 {
		fail(fmt.Errorf("a notification carries six values"))
		return
	}
	id, err := asInt(values[0])
	if err != nil {
		fail(err)
		return
	}
	c.mu.Lock()
	r := c.attached[uint32(id)]
	c.mu.Unlock()
	if r == nil {
		return // detached, or still being attached
	}
	cursor, err := resource.CursorFromWire(values[1], values[2])
	if err != nil {
		fail(err)
		return
	}
	index, err := asInt(values[4])
	if err != nil {
		fail(err)
		return
	}
	if action == packet.PropertyModified {
		date, _ := values[3].(time.Time)
		r.updateProperty(int(index), values[5], cursor, date)
	} else {
		r.applyEvent(int(index), values[5], cursor)
	}
}
