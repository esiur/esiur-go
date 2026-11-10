package ep

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/esiur/esiur-go/core"
	"github.com/esiur/esiur-go/data"
	"github.com/esiur/esiur-go/packet"
	"github.com/esiur/esiur-go/resource"
	"github.com/esiur/esiur-go/security"
)

// hostedSession is the server half of one connection: it answers the peer's requests (attach,
// invoke, set, subscribe, TypeDefs ...) and keeps the peer informed of the changes of every
// resource it attached to.
//
// Not ported yet, and answered NotImplemented: reattach, TypeDef synchronization, queries,
// creating, deleting and moving resources, streaming calls and journal queries.
type hostedSession struct {
	conn      *Connection
	warehouse *resource.Warehouse

	mu        sync.Mutex
	attached  map[uint32]func()
	events    map[uint32]map[int]bool
	attaching map[uint32]bool
}

func newHostedSession(c *Connection, w *resource.Warehouse) *hostedSession {
	return &hostedSession{conn: c, warehouse: w, attached: map[uint32]func(){}, events: map[uint32]map[int]bool{}, attaching: map[uint32]bool{}}
}

type refusal struct {
	kind    core.ErrorType
	code    core.ExceptionCode
	message string
}

func (r *refusal) Error() string { return r.message }

func refuse(code core.ExceptionCode, format string, args ...any) *refusal {
	return &refusal{core.Management, code, fmt.Sprintf(format, args...)}
}

type handlerFunc func(h *hostedSession, callbackID uint32, tdu *data.ParsedTdu) error

// Handlers that may run user code or wait on the peer run on their own goroutine; the others run
// in order on the reader, as esiur-ts runs them.
var hostedHandlers = map[uint8]struct {
	fn    handlerFunc
	async bool
}{
	packet.AttachResource:      {(*hostedSession).attach, false},
	packet.DetachResource:      {(*hostedSession).detach, false},
	packet.GetResourceIDByLink: {(*hostedSession).resourceIDByLink, false},
	packet.TypeDefByID:         {(*hostedSession).typeDefByID, false},
	packet.TypeDefByResourceID: {(*hostedSession).typeDefByResourceID, false},
	packet.InvokeFunction:      {(*hostedSession).invoke, true},
	packet.StaticCall:          {(*hostedSession).staticCall, true},
	packet.SetProperty:         {(*hostedSession).setProperty, false},
	packet.Subscribe:           {(*hostedSession).subscribe, false},
	packet.Unsubscribe:         {(*hostedSession).unsubscribe, false},
}

func (h *hostedSession) handles(action uint8) bool {
	_, ok := hostedHandlers[action]
	return ok
}

func (h *hostedSession) run(action uint8, callbackID uint32, tdu *data.ParsedTdu) {
	entry := hostedHandlers[action]
	exec := func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("esiur: request %d panicked: %v", action, r)
				_ = h.conn.SendError(core.Exception, callbackID, core.RuntimeException, fmt.Sprint(r))
			}
		}()
		if err := entry.fn(h, callbackID, tdu); err != nil {
			h.answerError(callbackID, err)
		}
	}
	if entry.async {
		go exec()
	} else {
		exec()
	}
}

// answerError turns whatever went wrong into the error reply it deserves.
func (h *hostedSession) answerError(callbackID uint32, err error) {
	var r *refusal
	var e *core.Error
	switch {
	case errors.As(err, &r):
		_ = h.conn.SendError(r.kind, callbackID, r.code, r.message)
	case errors.As(err, &e):
		_ = h.conn.SendError(e.Type, callbackID, e.Code, e.Message)
	case errors.Is(err, data.ErrParse):
		_ = h.conn.SendError(core.Management, callbackID, core.ParseError, err.Error())
	default:
		_ = h.conn.SendError(core.Exception, callbackID, core.RuntimeException, err.Error())
	}
}

func (h *hostedSession) close() {
	h.mu.Lock()
	stops := h.attached
	h.attached = map[uint32]func(){}
	h.events = map[uint32]map[int]bool{}
	h.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

// ---- helpers ------------------------------------------------------------------------------

func (h *hostedSession) values(tdu *data.ParsedTdu, minimum int) ([]any, error) {
	if tdu == nil {
		return nil, refuse(core.ParseError, "The request carries no value.")
	}
	value, err := h.conn.Decode(tdu)
	if err != nil {
		return nil, err
	}
	list, isList := value.([]any)
	if minimum == 1 && !isList {
		return []any{value}, nil
	}
	if !isList || len(list) < minimum {
		return nil, refuse(core.ParseError, "The request needs %d values.", minimum)
	}
	return list, nil
}

func integer(value any, what string) (int64, error) {
	if _, isBool := value.(bool); !isBool {
		if v, ok := data.ToInt64(value); ok {
			return v, nil
		}
	}
	return 0, refuse(core.ParseError, "The %s must be an integer.", what)
}

func (h *hostedSession) resource(id any) (resource.Resource, *resource.Instance, error) {
	n, err := integer(id, "resource id")
	if err != nil {
		return nil, nil, err
	}
	r := h.warehouse.GetByID(uint32(n))
	if r == nil || resource.InstanceOf(r) == nil {
		return nil, nil, refuse(core.ResourceNotFound, "")
	}
	return r, resource.InstanceOf(r), nil
}

func (h *hostedSession) permit(r resource.Resource, action security.ActionType, member any, code core.ExceptionCode) error {
	v := h.warehouse.Evaluate(r, h.conn.Session(), action, member, h.conn)
	if !v.Allowed {
		return refuse(code, "%s", v.Reason)
	}
	return nil
}

func hasReference(value any) bool {
	found := false
	walkReferences(value, func(data.ResourceID) { found = true })
	return found
}

// materialize replaces the resource references of a decoded argument with the resources: the
// ones this node hosts, and proxies for the ones the peer hosts.
func (h *hostedSession) materialize(ctx context.Context, value any) (any, error) {
	if !hasReference(value) {
		return value, nil
	}
	switch v := value.(type) {
	case data.ResourceID:
		if v.Local {
			r := h.warehouse.GetByID(v.ID)
			if r == nil {
				return nil, refuse(core.ResourceNotFound, "")
			}
			return r, nil
		}
		return h.conn.resolveResource(ctx, v.ID)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			m, err := h.materialize(ctx, item)
			if err != nil {
				return nil, err
			}
			out[i] = m
		}
		return out, nil
	case data.Map:
		out := make(data.Map, len(v))
		for i, e := range v {
			k, err := h.materialize(ctx, e.Key)
			if err != nil {
				return nil, err
			}
			val, err := h.materialize(ctx, e.Value)
			if err != nil {
				return nil, err
			}
			out[i] = data.MapEntry{Key: k, Value: val}
		}
		return out, nil
	}
	return value, nil
}

// ---- attach and detach --------------------------------------------------------------------

func (h *hostedSession) attach(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 1)
	if err != nil {
		return err
	}
	n, err := integer(values[0], "resource id")
	if err != nil {
		return err
	}
	id := uint32(n)
	h.mu.Lock()
	_, attached := h.attached[id]
	if attached || h.attaching[id] {
		h.mu.Unlock()
		return refuse(core.AlreadyAttached, "Resource %d is already attached or being attached by this connection.", id)
	}
	h.attaching[id] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.attaching, id)
		h.mu.Unlock()
	}()
	r, instance, err := h.resource(int64(id))
	if err != nil {
		return err
	}
	if err := h.permit(r, security.ActionAttach, nil, core.AttachDenied); err != nil {
		return err
	}
	cursor := instance.Cursor()
	composer := h.conn.Composer()
	var snapshot []byte
	for index := range instance.Type.Properties {
		for _, part := range []any{int64(instance.AgeOf(index)), instance.ModifiedAt(index), instance.ValueOf(index)} {
			b, err := composer.Compose(part)
			if err != nil {
				return err
			}
			snapshot = append(snapshot, b...)
		}
	}
	if snapshot == nil {
		snapshot = []byte{}
	}
	h.watch(id, instance)
	return h.conn.SendReply(packet.ReplyCompleted, callbackID,
		instance.Type.ID, cursor.Generation[:], cursor.Revision, instance.Link(), uint8(0), snapshot)
}

func (h *hostedSession) watch(id uint32, instance *resource.Instance) {
	stopProperty := instance.OnPropertyModified(func(change resource.PropertyModified) {
		h.notify(packet.PropertyModified, id, change.Cursor, change.RecordedAt, change.Index, change.Value)
	})
	stopEvent := instance.OnEventOccurred(func(o resource.EventOccurred) {
		event := instance.Type.Events[o.Index]
		if !event.AutoDelivered {
			h.mu.Lock()
			wanted := h.events[id][o.Index]
			h.mu.Unlock()
			if !wanted {
				return
			}
		}
		h.notify(packet.EventOccurred, id, o.Cursor, o.RecordedAt, o.Index, o.Value)
	})
	h.mu.Lock()
	h.attached[id] = func() { stopProperty(); stopEvent() }
	h.mu.Unlock()
}

func (h *hostedSession) notify(action uint8, id uint32, cursor resource.Cursor, at time.Time, index int, value any) {
	if err := h.conn.SendNotification(action, int64(id), cursor.Generation[:], cursor.Revision, at, index, value); err != nil {
		// A value this peer cannot be sent must not stop the others from being told.
		log.Printf("esiur: could not send a notification of resource %d: %v", id, err)
	}
}

func (h *hostedSession) detach(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 1)
	if err != nil {
		return err
	}
	r, instance, err := h.resource(values[0])
	if err != nil {
		return err
	}
	if err := h.permit(r, security.ActionDetach, nil, core.NotAllowed); err != nil {
		return err
	}
	h.mu.Lock()
	stop := h.attached[instance.ID]
	delete(h.attached, instance.ID)
	delete(h.events, instance.ID)
	h.mu.Unlock()
	if stop != nil {
		stop()
	}
	return h.conn.SendReply(packet.ReplyCompleted, callbackID)
}

// ---- links and types ----------------------------------------------------------------------

func (h *hostedSession) resourceIDByLink(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 1)
	if err != nil {
		return err
	}
	link, _ := values[0].(string)
	r, err := h.warehouse.Query(context.Background(), link)
	if err != nil {
		return err
	}
	if r == nil || resource.InstanceOf(r) == nil {
		return refuse(core.ResourceNotFound, "")
	}
	return h.conn.SendReply(packet.ReplyCompleted, callbackID, int64(resource.InstanceOf(r).ID))
}

func (h *hostedSession) typeDefReply(callbackID uint32, info *data.TypeDefInfo) error {
	// Like esiur-ts, the definition travels as raw data holding a complete TypeDef TDU.
	raw, err := (&data.Composer{Types: h.warehouse.Registry}).Compose(info)
	if err != nil {
		return err
	}
	return h.conn.SendReply(packet.ReplyCompleted, callbackID, raw)
}

func (h *hostedSession) typeDefByID(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 1)
	if err != nil {
		return err
	}
	id, err := integer(values[0], "type id")
	if err != nil {
		return err
	}
	hosted, ok := h.warehouse.TypeByID(uint64(id))
	if !ok {
		return refuse(core.TypeDefNotFound, "")
	}
	if err := h.permit(nil, security.ActionViewTypeDef, nil, core.NotAllowed); err != nil {
		return err
	}
	return h.typeDefReply(callbackID, hosted.Info)
}

func (h *hostedSession) typeDefByResourceID(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 1)
	if err != nil {
		return err
	}
	r, instance, err := h.resource(values[0])
	if err != nil {
		return err
	}
	if err := h.permit(r, security.ActionViewTypeDef, nil, core.NotAllowed); err != nil {
		return err
	}
	return h.typeDefReply(callbackID, instance.Type.Info)
}

// ---- calls and writes ---------------------------------------------------------------------

func (h *hostedSession) arguments(ctx context.Context, raw any) ([]any, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		list = asList(raw)
		if list == nil {
			return nil, refuse(core.ParseError, "The arguments must be a list.")
		}
	}
	out := make([]any, len(list))
	for i, item := range list {
		m, err := h.materialize(ctx, item)
		if err != nil {
			return nil, err
		}
		out[i] = m
	}
	return out, nil
}

func (h *hostedSession) invoke(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 2)
	if err != nil {
		return err
	}
	r, instance, err := h.resource(values[0])
	if err != nil {
		return err
	}
	position, err := integer(values[1], "function index")
	if err != nil {
		return err
	}
	if position < 0 || int(position) >= len(instance.Type.Functions) {
		return refuse(core.MethodNotFound, "")
	}
	function := &instance.Type.Functions[position]
	member := instance.Type.TypeDef.FunctionAt(int(position))
	if err := h.permit(r, security.ActionExecute, member, core.AccessDenied); err != nil {
		return err
	}
	var raw any
	if len(values) > 2 {
		raw = values[2]
	}
	ctx := withConnection(context.Background(), h.conn)
	args, err := h.arguments(ctx, raw)
	if err != nil {
		return err
	}
	result, err := function.Call(ctx, r, args)
	if err != nil {
		var e *core.Error
		if errors.As(err, &e) {
			return h.conn.SendError(e.Type, callbackID, e.Code, e.Message)
		}
		return h.conn.SendError(core.Exception, callbackID, core.RuntimeException, err.Error())
	}
	if function.HasResult {
		return h.conn.SendReply(packet.ReplyCompleted, callbackID, result)
	}
	return h.conn.SendReply(packet.ReplyCompleted, callbackID, nil)
}

func (h *hostedSession) staticCall(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 2)
	if err != nil {
		return err
	}
	if _, err := integer(values[0], "type id"); err != nil {
		return err
	}
	// Go resources export no static functions yet.
	return refuse(core.MethodNotFound, "")
}

func (h *hostedSession) setProperty(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 3)
	if err != nil {
		return err
	}
	r, instance, err := h.resource(values[0])
	if err != nil {
		return err
	}
	position, err := integer(values[1], "property index")
	if err != nil {
		return err
	}
	if position < 0 || int(position) >= len(instance.Type.Properties) {
		return refuse(core.PropertyNotFound, "")
	}
	property := instance.Type.Properties[position]
	member := instance.Type.TypeDef.PropertyAt(int(position))
	if err := h.permit(r, security.ActionSetProperty, member, core.AccessDenied); err != nil {
		return err
	}
	if property.ReadOnly {
		return refuse(core.ReadOnlyProperty, "'%s' is read-only.", property.Name)
	}
	apply := func(value any) error {
		if err := instance.SetValue(int(position), value); err != nil {
			return refuse(core.ParseError, "%v", err)
		}
		return h.conn.SendReply(packet.ReplyCompleted, callbackID)
	}
	if !hasReference(values[2]) {
		return apply(values[2])
	}
	// Resolving the peer's references may wait on the peer: do it off the reader.
	go func() {
		value, err := h.materialize(withConnection(context.Background(), h.conn), values[2])
		if err == nil {
			err = apply(value)
		}
		if err != nil {
			h.answerError(callbackID, err)
		}
	}()
	return nil
}

// ---- events -------------------------------------------------------------------------------

func (h *hostedSession) eventTarget(values []any) (resource.Resource, *resource.Instance, int, error) {
	r, instance, err := h.resource(values[0])
	if err != nil {
		return nil, nil, 0, err
	}
	h.mu.Lock()
	_, attached := h.attached[instance.ID]
	h.mu.Unlock()
	if !attached {
		return nil, nil, 0, refuse(core.NotAttached, "")
	}
	index, err := integer(values[1], "event index")
	if err != nil {
		return nil, nil, 0, err
	}
	if index < 0 || int(index) >= len(instance.Type.Events) {
		return nil, nil, 0, refuse(core.GeneralFailure, "")
	}
	return r, instance, int(index), nil
}

func (h *hostedSession) subscribe(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 2)
	if err != nil {
		return err
	}
	r, instance, index, err := h.eventTarget(values)
	if err != nil {
		return err
	}
	if instance.Type.Events[index].AutoDelivered {
		return refuse(core.NotSubscribable, "")
	}
	member := instance.Type.TypeDef.EventAt(index)
	if err := h.permit(r, security.ActionSubscribe, member, core.AccessDenied); err != nil {
		return err
	}
	if err := h.permit(r, security.ActionReceiveEvent, member, core.NotAllowed); err != nil {
		return err
	}
	h.mu.Lock()
	subscribed := h.events[instance.ID]
	if subscribed == nil {
		subscribed = map[int]bool{}
		h.events[instance.ID] = subscribed
	}
	if subscribed[index] {
		h.mu.Unlock()
		return refuse(core.AlreadyListened, "")
	}
	subscribed[index] = true
	h.mu.Unlock()
	head := instance.Cursor()
	return h.conn.SendReply(packet.ReplyCompleted, callbackID, head.Generation[:], head.Revision)
}

func (h *hostedSession) unsubscribe(callbackID uint32, tdu *data.ParsedTdu) error {
	values, err := h.values(tdu, 2)
	if err != nil {
		return err
	}
	r, instance, index, err := h.eventTarget(values)
	if err != nil {
		return err
	}
	h.mu.Lock()
	subscribed := h.events[instance.ID][index]
	h.mu.Unlock()
	if !subscribed {
		return refuse(core.AlreadyUnsubscribed, "")
	}
	if err := h.permit(r, security.ActionUnsubscribe, instance.Type.TypeDef.EventAt(index), core.AccessDenied); err != nil {
		return err
	}
	h.mu.Lock()
	delete(h.events[instance.ID], index)
	h.mu.Unlock()
	return h.conn.SendReply(packet.ReplyCompleted, callbackID)
}

type connectionKey struct{}

func withConnection(ctx context.Context, c *Connection) context.Context {
	return context.WithValue(ctx, connectionKey{}, c)
}

// ConnectionFrom returns the connection a hosted function was called through (for functions
// that take a context.Context first).
func ConnectionFrom(ctx context.Context) *Connection {
	c, _ := ctx.Value(connectionKey{}).(*Connection)
	return c
}
