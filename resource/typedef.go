// Package resource is what a node hosts: resources, their instances, stores and the warehouse
// (port of esiur-ts resource/*), plus the views of type definitions shared with clients.
package resource

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/esiur/esiur-go/data"
)

// TypeDef is a type's exported surface, as members addressable by index and by name. Names are
// matched exactly first, then ignoring case and underscores, so "say_hi" finds a member a peer
// calls "sayHi" or "SayHi".
type TypeDef struct {
	Info       *data.TypeDefInfo
	Properties []*data.PropertyDefInfo
	Functions  []*data.FunctionDefInfo
	Events     []*data.EventDefInfo
	Constants  []*data.ConstantDefInfo
	props      map[int]*data.PropertyDefInfo
	funcs      map[int]*data.FunctionDefInfo
	events     map[int]*data.EventDefInfo
}

// NewTypeDef builds the lookups of info.
func NewTypeDef(info *data.TypeDefInfo) *TypeDef {
	t := &TypeDef{Info: info, props: map[int]*data.PropertyDefInfo{}, funcs: map[int]*data.FunctionDefInfo{}, events: map[int]*data.EventDefInfo{}}
	for i := range info.Properties {
		p := &info.Properties[i]
		t.Properties = append(t.Properties, p)
		t.props[p.Index] = p
	}
	for i := range info.Functions {
		f := &info.Functions[i]
		t.Functions = append(t.Functions, f)
		t.funcs[f.Index] = f
	}
	for i := range info.Events {
		e := &info.Events[i]
		t.Events = append(t.Events, e)
		t.events[e.Index] = e
	}
	for i := range info.Constants {
		t.Constants = append(t.Constants, &info.Constants[i])
	}
	return t
}

func (t *TypeDef) ID() uint64                             { return t.Info.ID }
func (t *TypeDef) Name() string                           { return t.Info.Name }
func (t *TypeDef) String() string                         { return fmt.Sprintf("TypeDef(%q, id=%d)", t.Name(), t.ID()) }
func (t *TypeDef) PropertyAt(i int) *data.PropertyDefInfo { return t.props[i] }
func (t *TypeDef) FunctionAt(i int) *data.FunctionDefInfo { return t.funcs[i] }
func (t *TypeDef) EventAt(i int) *data.EventDefInfo       { return t.events[i] }

func normalize(name string) string { return strings.ToLower(strings.ReplaceAll(name, "_", "")) }

func find[M any](members []*M, nameOf func(*M) string, name string) (*M, error) {
	for _, m := range members {
		if nameOf(m) == name {
			return m, nil
		}
	}
	wanted := normalize(name)
	var match *M
	for _, m := range members {
		if normalize(nameOf(m)) == wanted {
			if match != nil {
				return nil, fmt.Errorf("esiur: %q matches more than one member", name)
			}
			match = m
		}
	}
	return match, nil
}

// FindProperty finds a property by name (nil when there is none).
func (t *TypeDef) FindProperty(name string) (*data.PropertyDefInfo, error) {
	return find(t.Properties, func(m *data.PropertyDefInfo) string { return m.Name }, name)
}

// FindFunction finds a function by name (nil when there is none).
func (t *TypeDef) FindFunction(name string) (*data.FunctionDefInfo, error) {
	return find(t.Functions, func(m *data.FunctionDefInfo) string { return m.Name }, name)
}

// FindEvent finds an event by name (nil when there is none).
func (t *TypeDef) FindEvent(name string) (*data.EventDefInfo, error) {
	return find(t.Events, func(m *data.EventDefInfo) string { return m.Name }, name)
}

// IsReadOnly reports a read-only property.
func IsReadOnly(p *data.PropertyDefInfo) bool { return p.Flags&data.PropertyReadOnly != 0 }

// IsStatic reports a static function.
func IsStatic(f *data.FunctionDefInfo) bool { return f.Flags&data.FunctionStatic != 0 }

// IsSubscribable reports whether the peer pushes this event only to subscribers (the default);
// an auto-delivered event reaches every attached connection.
func IsSubscribable(e *data.EventDefInfo) bool { return e.Flags&data.EventAutoDelivered == 0 }

// IsHistorical reports a historical event.
func IsHistorical(e *data.EventDefInfo) bool { return e.Flags&data.EventHistorical != 0 }

// Cursor is a position in a resource's ordered stream of property and event changes: the id of
// the stream (its generation) and a revision within it.
type Cursor struct {
	Generation data.UUID
	Revision   uint64
}

// IsEmpty reports the zero cursor.
func (c Cursor) IsEmpty() bool { return c == Cursor{} }

func (c Cursor) String() string {
	return hex.EncodeToString(c.Generation[:]) + ":" + fmt.Sprint(c.Revision)
}

// CursorFromWire builds a cursor from the two values it travels as: 16 raw bytes and an
// integer.
func CursorFromWire(generation, revision any) (Cursor, error) {
	g, ok := generation.([]byte)
	r, isInt := asUint(revision)
	if !ok || len(g) != 16 || !isInt {
		return Cursor{}, fmt.Errorf("esiur: a resource cursor is a 16-byte generation and an integer revision")
	}
	var c Cursor
	copy(c.Generation[:], g)
	c.Revision = r
	return c, nil
}

func asUint(v any) (uint64, bool) {
	if i, ok := data.ToInt64(v); ok && i >= 0 {
		return uint64(i), true
	}
	if u, ok := v.(uint64); ok {
		return u, true
	}
	return 0, false
}
