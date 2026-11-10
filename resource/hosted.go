package resource

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"github.com/esiur/esiur-go/data"
)

// HostedProperty is one exported property of a hosted type.
type HostedProperty struct {
	Name     string
	ReadOnly bool
	Type     reflect.Type
	field    []int
}

// HostedFunction is one exported function of a hosted type.
type HostedFunction struct {
	Name string
	// Method is the Go method; its receiver is the resource pointer.
	Method     reflect.Method
	Params     []reflect.Type // excluding the receiver and a leading context.Context
	WithCtx    bool
	ReturnsErr bool
	HasResult  bool
}

// HostedEvent is one exported event of a hosted type.
type HostedEvent struct {
	Name          string
	AutoDelivered bool
	Type          reflect.Type
	field         []int
}

// HostedType is a hosted Go type's exported surface: its members by wire index, and the
// definition peers are shown.
type HostedType struct {
	GoType     reflect.Type // the struct type
	ID         uint64
	Info       *data.TypeDefInfo
	TypeDef    *TypeDef
	Properties []HostedProperty
	Functions  []HostedFunction
	Events     []HostedEvent
}

func (h *HostedType) Name() string { return h.Info.Name }

var (
	contextType = reflect.TypeOf((*context.Context)(nil)).Elem()
	errorType   = reflect.TypeOf((*error)(nil)).Elem()
	excluded    = map[string]bool{"Create": true, "Handle": true, "Description": true, "FunctionNames": true}
)

// FunctionNamer is implemented by a resource type that exports some functions under other names
// than LowerCamel of the Go method name: it maps Go method names to exported names.
type FunctionNamer interface {
	FunctionNames() map[string]string
}

func init() {
	t := reflect.TypeOf(&Base{})
	for i := 0; i < t.NumMethod(); i++ {
		excluded[t.Method(i).Name] = true
	}
}

func storeMethods() map[string]bool {
	out := map[string]bool{}
	st := reflect.TypeOf((*Store)(nil)).Elem()
	for i := 0; i < st.NumMethod(); i++ {
		out[st.Method(i).Name] = true
	}
	return out
}

// LowerCamel is the default exported name of a Go member: its first word in lower case
// ("Greet" -> "greet", "URLPath" -> "urlPath", "ID" -> "id").
func LowerCamel(name string) string {
	r := []rune(name)
	n := 0
	for n < len(r) && unicode.IsUpper(r[n]) {
		n++
	}
	switch {
	case n == 0:
		return name
	case n == 1 || n == len(r):
		// "Greet" -> "greet", "ID" -> "id"
	default:
		n-- // "URLPath": keep the "P" of "Path"
	}
	for i := 0; i < n; i++ {
		r[i] = unicode.ToLower(r[i])
	}
	return string(r)
}

func parseTag(f reflect.StructField) (name string, opts map[string]bool) {
	opts = map[string]bool{}
	tag := f.Tag.Get("esiur")
	parts := strings.Split(tag, ",")
	name = strings.TrimSpace(parts[0])
	for _, o := range parts[1:] {
		opts[strings.TrimSpace(o)] = true
	}
	if name == "" {
		name = LowerCamel(f.Name)
	}
	return name, opts
}

// describe builds the definition of the resource type t (a pointer to struct) under id.
func describe(t reflect.Type, id uint64, types *data.TypeRegistry, nameOf data.NameOf) (*HostedType, error) {
	if t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("esiur: a resource must be a pointer to a struct, got %s", t)
	}
	st := t.Elem()
	h := &HostedType{GoType: st, ID: id}
	info := &data.TypeDefInfo{ID: id, Kind: data.KindResource, Name: st.Name()}
	if d, ok := reflect.New(st).Interface().(interface{ Description() string }); ok {
		if s := d.Description(); s != "" {
			info.Description = &s
		}
	}

	seen := map[string]bool{}
	for _, f := range reflect.VisibleFields(st) {
		if !f.IsExported() || f.Tag.Get("esiur") == "-" {
			continue
		}
		pt := reflect.PointerTo(f.Type)
		switch {
		case pt.Implements(propertyFieldType):
			name, opts := parseTag(f)
			if seen["p:"+name] {
				return nil, fmt.Errorf("esiur: %s exports two properties named %s", st.Name(), name)
			}
			seen["p:"+name] = true
			vt := reflect.New(f.Type).Interface().(propertyField).valueType()
			hp := HostedProperty{Name: name, ReadOnly: opts["readonly"], Type: vt, field: f.Index}
			flags := 0
			if hp.ReadOnly {
				flags = data.PropertyReadOnly
			}
			pi := data.PropertyDefInfo{
				MemberDefInfo: data.MemberDefInfo{Index: len(h.Properties), Name: name, Flags: flags},
				ValueType:     data.TruOf(vt, types),
			}
			if doc := f.Tag.Get("doc"); doc != "" {
				pi.Description = &doc
			}
			h.Properties = append(h.Properties, hp)
			info.Properties = append(info.Properties, pi)
		case pt.Implements(eventFieldType):
			name, opts := parseTag(f)
			if seen["e:"+name] {
				return nil, fmt.Errorf("esiur: %s exports two events named %s", st.Name(), name)
			}
			seen["e:"+name] = true
			vt := reflect.New(f.Type).Interface().(eventField).valueType()
			he := HostedEvent{Name: name, AutoDelivered: opts["auto"], Type: vt, field: f.Index}
			flags := 0
			if he.AutoDelivered {
				flags = data.EventAutoDelivered
			}
			ei := data.EventDefInfo{
				MemberDefInfo: data.MemberDefInfo{Index: len(h.Events), Name: name, Flags: flags},
				ArgumentType:  data.TruOf(vt, types),
			}
			if arg := f.Tag.Get("arg"); arg != "" {
				ei.ArgumentName = &arg
			}
			if doc := f.Tag.Get("doc"); doc != "" {
				ei.Description = &doc
			}
			h.Events = append(h.Events, he)
			info.Events = append(info.Events, ei)
		}
	}

	renames := map[string]string{}
	if n, ok := reflect.New(st).Interface().(FunctionNamer); ok {
		renames = n.FunctionNames()
	}
	var skip map[string]bool
	if t.Implements(reflect.TypeOf((*Store)(nil)).Elem()) {
		skip = storeMethods()
	}
	for i := 0; i < t.NumMethod(); i++ {
		m := t.Method(i)
		if excluded[m.Name] || skip[m.Name] || m.Type.IsVariadic() {
			continue
		}
		name := LowerCamel(m.Name)
		if renamed, ok := renames[m.Name]; ok {
			name = renamed
		}
		hf := HostedFunction{Name: name, Method: m}
		in := m.Type.NumIn()
		start := 1
		if in > 1 && m.Type.In(1) == contextType {
			hf.WithCtx = true
			start = 2
		}
		for p := start; p < in; p++ {
			hf.Params = append(hf.Params, m.Type.In(p))
		}
		var result reflect.Type
		switch m.Type.NumOut() {
		case 0:
		case 1:
			if m.Type.Out(0) == errorType {
				hf.ReturnsErr = true
			} else {
				hf.HasResult, result = true, m.Type.Out(0)
			}
		case 2:
			if m.Type.Out(1) != errorType {
				continue // not an exportable shape
			}
			hf.HasResult, hf.ReturnsErr, result = true, true, m.Type.Out(0)
		default:
			continue
		}
		returns := data.Tru(data.T.Void)
		if hf.HasResult {
			returns = data.TruOf(result, types)
		}
		fi := data.FunctionDefInfo{
			MemberDefInfo: data.MemberDefInfo{Index: len(h.Functions), Name: hf.Name},
			ReturnType:    returns,
			Arguments:     []data.ArgumentDefInfo{},
		}
		for p, pt := range hf.Params {
			fi.Arguments = append(fi.Arguments, data.ArgumentDefInfo{
				MemberDefInfo: data.MemberDefInfo{Index: p, Name: fmt.Sprintf("arg%d", p)},
				ValueType:     data.TruOf(pt, types),
			})
		}
		h.Functions = append(h.Functions, hf)
		info.Functions = append(info.Functions, fi)
	}
	if info.Properties == nil {
		info.Properties = []data.PropertyDefInfo{}
	}
	if info.Functions == nil {
		info.Functions = []data.FunctionDefInfo{}
	}
	if info.Events == nil {
		info.Events = []data.EventDefInfo{}
	}
	info.Constants = []data.ConstantDefInfo{}
	sig, err := data.TypeDefSignature(info, nameOf)
	if err != nil {
		return nil, err
	}
	info.Signature = &sig
	h.Info = info
	h.TypeDef = NewTypeDef(info)
	return h, nil
}

// Call runs function f on resource r (a pointer to the hosted struct) with already converted
// arguments.
func (f *HostedFunction) Call(ctx context.Context, r Resource, args []any) (any, error) {
	if len(args) != len(f.Params) {
		return nil, fmt.Errorf("esiur: %s takes %d arguments, got %d", f.Name, len(f.Params), len(args))
	}
	in := []reflect.Value{reflect.ValueOf(r)}
	if f.WithCtx {
		in = append(in, reflect.ValueOf(ctx))
	}
	for i, pt := range f.Params {
		var arg any
		if i < len(args) {
			arg = args[i]
		}
		v, err := data.Convert(arg, pt)
		if err != nil {
			return nil, fmt.Errorf("esiur: argument %d of %s: %w", i, f.Name, err)
		}
		in = append(in, v)
	}
	out := f.Method.Func.Call(in)
	var result any
	if f.HasResult {
		result = out[0].Interface()
	}
	if f.ReturnsErr {
		if e := out[len(out)-1]; !e.IsNil() {
			return nil, e.Interface().(error)
		}
	}
	return result, nil
}
