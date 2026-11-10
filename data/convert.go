package data

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"
)

var (
	typeAny        = reflect.TypeOf((*any)(nil)).Elem()
	typeBytes      = reflect.TypeOf([]byte(nil))
	typeTime       = reflect.TypeOf(time.Time{})
	typeUUID       = reflect.TypeOf(UUID{})
	typeDecimal    = reflect.TypeOf(Decimal{})
	typeInt128     = reflect.TypeOf(Int128{})
	typeUInt128    = reflect.TypeOf(UInt128{})
	typeChar16     = reflect.TypeOf(Char16(0))
	typeMap        = reflect.TypeOf(Map(nil))
	typeTypedTuple = reflect.TypeOf(TypedTuple{})
	typeTru        = reflect.TypeOf((*Tru)(nil)).Elem()
	typeString     = reflect.TypeOf("")
	typeResourceID = reflect.TypeOf(ResourceID{})
	typeIndexed    = reflect.TypeOf((*IndexedStructure)(nil)).Elem()
)

// resourceInterfaces are the interface types that mark a Go type as a resource; the resource
// package registers its own on init.
var resourceInterfaces []reflect.Type

// RegisterResourceInterface marks every type implementing iface (an interface type) as a
// resource, so it maps to the Resource Tru.
func RegisterResourceInterface(iface reflect.Type) {
	resourceInterfaces = append(resourceInterfaces, iface)
}

func isResourceType(t reflect.Type) bool {
	for _, iface := range resourceInterfaces {
		if t == iface || (iface.Kind() == reflect.Interface && t.Kind() != reflect.Interface && t.Implements(iface)) {
			return true
		}
	}
	return false
}

func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case uint8:
		return int64(x), true
	case uint16:
		return int64(x), true
	case uint32:
		return int64(x), true
	case Char16:
		return int64(x), true
	case uint:
		if uint64(x) <= math.MaxInt64 {
			return int64(x), true
		}
	case uint64:
		if x <= math.MaxInt64 {
			return int64(x), true
		}
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if rv.Uint() <= math.MaxInt64 {
			return int64(rv.Uint()), true
		}
	}
	return 0, false
}

func asUint(v any) (uint64, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if rv.Int() >= 0 {
			return uint64(rv.Int()), true
		}
	}
	return 0, false
}

func asFloat(v any) (float64, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), true
	}
	return 0, false
}

// ToInt64 converts any integer value (and whole floats) to int64.
func ToInt64(v any) (int64, bool) {
	if i, ok := asInt(v); ok {
		return i, true
	}
	if f, ok := asFloat(v); ok && f == math.Trunc(f) && f >= math.MinInt64 && f <= math.MaxInt64 {
		return int64(f), true
	}
	return 0, false
}

// As converts a decoded value to T (see Convert).
func As[T any](value any) (T, error) {
	var zero T
	rv, err := Convert(value, reflect.TypeOf(&zero).Elem())
	if err != nil {
		return zero, err
	}
	return rv.Interface().(T), nil
}

func convertErr(value any, t reflect.Type) error {
	return parseErr("Cannot convert %T to %s.", value, t)
}

// Convert converts a decoded value to the Go type t: numbers between widths (failing when the
// value does not fit), lists to slices, maps to Go maps, indexed maps to indexed structures and
// string-keyed maps to structs. nil converts to the zero value.
func Convert(value any, t reflect.Type) (reflect.Value, error) {
	if value == nil {
		return reflect.Zero(t), nil
	}
	if rv, ok := value.(reflect.Value); ok {
		value = rv.Interface()
	}
	vt := reflect.TypeOf(value)
	if vt == t || (t.Kind() == reflect.Interface && vt.Implements(t)) {
		return reflect.ValueOf(value).Convert(t), nil
	}

	switch t.Kind() {
	case reflect.Pointer:
		if vt.Kind() == reflect.Pointer && vt.AssignableTo(t) {
			return reflect.ValueOf(value), nil
		}
		inner, err := Convert(value, t.Elem())
		if err != nil {
			return reflect.Value{}, err
		}
		p := reflect.New(t.Elem())
		p.Elem().Set(inner)
		return p, nil
	case reflect.Interface:
		return reflect.Value{}, convertErr(value, t)
	case reflect.Bool:
		if b, ok := value.(bool); ok {
			return reflect.ValueOf(b).Convert(t), nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if i, ok := ToInt64(value); ok {
			out := reflect.New(t).Elem()
			if out.OverflowInt(i) {
				return reflect.Value{}, parseErr("Value %d does not fit in %s.", i, t)
			}
			out.SetInt(i)
			return out, nil
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		u, ok := asUint(value)
		if !ok {
			if f, isF := asFloat(value); isF && f >= 0 && f == math.Trunc(f) && f <= math.MaxUint64 {
				u, ok = uint64(f), true
			}
		}
		if ok {
			out := reflect.New(t).Elem()
			if out.OverflowUint(u) {
				return reflect.Value{}, parseErr("Value %d does not fit in %s.", u, t)
			}
			out.SetUint(u)
			return out, nil
		}
	case reflect.Float32, reflect.Float64:
		if f, ok := asFloat(value); ok {
			return reflect.ValueOf(f).Convert(t), nil
		}
	case reflect.String:
		switch s := value.(type) {
		case string:
			return reflect.ValueOf(s).Convert(t), nil
		case ResourceLink:
			return reflect.ValueOf(string(s)).Convert(t), nil
		}
	case reflect.Slice:
		return convertSlice(value, t)
	case reflect.Array:
		src := reflect.ValueOf(value)
		if (src.Kind() == reflect.Slice || src.Kind() == reflect.Array) && src.Len() == t.Len() {
			out := reflect.New(t).Elem()
			for i := 0; i < src.Len(); i++ {
				item, err := Convert(src.Index(i).Interface(), t.Elem())
				if err != nil {
					return reflect.Value{}, err
				}
				out.Index(i).Set(item)
			}
			return out, nil
		}
	case reflect.Map:
		entries, ok := MapEntries(value)
		if !ok {
			break
		}
		out := reflect.MakeMapWithSize(t, len(entries))
		for _, e := range entries {
			k, err := Convert(e.Key, t.Key())
			if err != nil {
				return reflect.Value{}, err
			}
			v, err := Convert(e.Value, t.Elem())
			if err != nil {
				return reflect.Value{}, err
			}
			out.SetMapIndex(k, v)
		}
		return out, nil
	case reflect.Struct:
		if t == typeMap {
			break
		}
		if reflect.PointerTo(t).Implements(typeIndexed) || t.Implements(typeIndexed) {
			return fromIndexedMap(value, t)
		}
		if entries, ok := MapEntries(value); ok {
			return structFromEntries(entries, t)
		}
	}
	if vt.ConvertibleTo(t) && vt.Kind() == t.Kind() {
		return reflect.ValueOf(value).Convert(t), nil
	}
	return reflect.Value{}, convertErr(value, t)
}

func convertSlice(value any, t reflect.Type) (reflect.Value, error) {
	var items []any
	switch v := value.(type) {
	case TypedList:
		value = v.Values
	case TypedTuple:
		items = v.Values
	}
	if items == nil {
		src := reflect.ValueOf(value)
		if src.Kind() != reflect.Slice && src.Kind() != reflect.Array {
			if s, ok := value.(string); ok && t.Elem().Kind() == reflect.Uint8 {
				return reflect.ValueOf([]byte(s)).Convert(t), nil
			}
			return reflect.Value{}, convertErr(value, t)
		}
		if src.Type().ConvertibleTo(t) && src.Kind() == reflect.Slice {
			return src.Convert(t), nil
		}
		items = make([]any, src.Len())
		for i := range items {
			items[i] = src.Index(i).Interface()
		}
	}
	out := reflect.MakeSlice(t, len(items), len(items))
	for i, item := range items {
		v, err := Convert(item, t.Elem())
		if err != nil {
			return reflect.Value{}, err
		}
		out.Index(i).Set(v)
	}
	return out, nil
}

// MapEntries lists the entries of a Map, a TypedMap or any Go map (Go maps sorted by key).
func MapEntries(value any) (Map, bool) {
	switch m := value.(type) {
	case Map:
		return m, true
	case *Map:
		return *m, true
	case TypedMap:
		return m.Entries, true
	case *TypedMap:
		return m.Entries, true
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Map {
		return nil, false
	}
	keys := rv.MapKeys()
	sortKeys(keys)
	out := make(Map, len(keys))
	for i, k := range keys {
		out[i] = MapEntry{k.Interface(), rv.MapIndex(k).Interface()}
	}
	return out, true
}

func sortKeys(keys []reflect.Value) {
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Kind() == reflect.Interface {
			a = a.Elem()
		}
		if b.Kind() == reflect.Interface {
			b = b.Elem()
		}
		if a.IsValid() && b.IsValid() && a.Kind() == b.Kind() {
			switch a.Kind() {
			case reflect.String:
				return a.String() < b.String()
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				return a.Int() < b.Int()
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				return a.Uint() < b.Uint()
			case reflect.Float32, reflect.Float64:
				return a.Float() < b.Float()
			}
		}
		return fmt.Sprint(a) < fmt.Sprint(b)
	})
}

// structFromEntries fills a struct's exported fields from a string-keyed map (a record decoded
// without a Go type, for example).
func structFromEntries(entries Map, t reflect.Type) (reflect.Value, error) {
	out := reflect.New(t).Elem()
	for _, e := range entries {
		name, ok := e.Key.(string)
		if !ok {
			return reflect.Value{}, parseErr("Cannot fill %s from a map with %T keys.", t, e.Key)
		}
		field, ok := fieldByWireName(t, name)
		if !ok {
			continue
		}
		v, err := Convert(e.Value, field.Type)
		if err != nil {
			return reflect.Value{}, err
		}
		out.FieldByIndex(field.Index).Set(v)
	}
	return out, nil
}

func fieldByWireName(t reflect.Type, name string) (reflect.StructField, bool) {
	for _, f := range reflect.VisibleFields(t) {
		if !f.IsExported() || f.Anonymous {
			continue
		}
		if wireName(f) == name {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

// wireName is a record field's name on the wire: its `esiur:"name"` tag, else the field name.
func wireName(f reflect.StructField) string {
	if tag := f.Tag.Get("esiur"); tag != "" && tag != "-" {
		return tag
	}
	return f.Name
}

// GoTypeOf is the Go type a value declared with tru decodes to inside a typed collection.
// Nullable and dynamic types decode to any.
func GoTypeOf(tru Tru, types *TypeRegistry) reflect.Type {
	if tru == nil || tru.Nullable() {
		return typeAny
	}
	switch tt := tru.(type) {
	case TruPrimitive:
		switch tt.Kind {
		case TruBool:
			return reflect.TypeOf(false)
		case TruUInt8:
			return reflect.TypeOf(uint8(0))
		case TruInt8:
			return reflect.TypeOf(int8(0))
		case TruChar:
			return typeChar16
		case TruUInt16:
			return reflect.TypeOf(uint16(0))
		case TruInt16:
			return reflect.TypeOf(int16(0))
		case TruUInt32:
			return reflect.TypeOf(uint32(0))
		case TruInt32:
			return reflect.TypeOf(int32(0))
		case TruFloat32:
			return reflect.TypeOf(float32(0))
		case TruUInt64:
			return reflect.TypeOf(uint64(0))
		case TruInt64:
			return reflect.TypeOf(int64(0))
		case TruFloat64:
			return reflect.TypeOf(float64(0))
		case TruDateTime:
			return typeTime
		case TruUInt128:
			return typeUInt128
		case TruInt128:
			return typeInt128
		case TruDecimal:
			return typeDecimal
		case TruString:
			return typeString
		case TruRawData:
			return typeBytes
		case TruList:
			return reflect.TypeOf([]any(nil))
		case TruMap:
			return typeMap
		}
	case TruComposite:
		switch {
		case tt.Kind == TruTypedList:
			return reflect.SliceOf(GoTypeOf(tt.SubTypes[0], types))
		case tt.Kind == TruTypedMap:
			k, v := GoTypeOf(tt.SubTypes[0], types), GoTypeOf(tt.SubTypes[1], types)
			if k.Kind() == reflect.Interface || !k.Comparable() {
				return typeMap
			}
			return reflect.MapOf(k, v)
		case tt.Kind.IsTuple():
			return typeTypedTuple
		}
	case TruTypeDef:
		if types != nil && !tt.Remote {
			if def, ok := types.ByID(tt.TypeID); ok && def.GoType != nil {
				return def.GoType
			}
		}
	}
	return typeAny
}

// TruOf is the Tru a Go type is declared as on the wire. Registered records and enums need the
// registry that registered them.
func TruOf(t reflect.Type, types *TypeRegistry) Tru {
	if t == nil {
		return T.Void
	}
	if types != nil {
		if def, ok := types.ByGoType(t); ok {
			return TruTypeDef{TypeID: def.ID}
		}
	}
	switch t {
	case typeAny:
		return T.Dynamic
	case typeBytes:
		return T.RawData
	case typeTime:
		return T.DateTime
	case typeDecimal:
		return T.Decimal
	case typeInt128:
		return T.I128
	case typeUInt128:
		return T.U128
	case typeChar16:
		return T.Char
	case typeMap:
		return T.DynMap
	}
	if isResourceType(t) {
		return T.Resource
	}
	if t.Implements(typeTru) {
		return T.Dynamic
	}
	switch t.Kind() {
	case reflect.Pointer:
		return TruOf(t.Elem(), types).WithNullable(true)
	case reflect.Bool:
		return T.Bool
	case reflect.Int8:
		return T.I8
	case reflect.Uint8:
		return T.U8
	case reflect.Int16:
		return T.I16
	case reflect.Uint16:
		return T.U16
	case reflect.Int32:
		return T.I32
	case reflect.Uint32:
		return T.U32
	case reflect.Int, reflect.Int64:
		return T.I64
	case reflect.Uint, reflect.Uint64:
		return T.U64
	case reflect.Float32:
		return T.F32
	case reflect.Float64:
		return T.F64
	case reflect.String:
		return T.String
	case reflect.Slice, reflect.Array:
		if t.Elem() == typeAny {
			return T.DynList
		}
		return T.List(TruOf(t.Elem(), types))
	case reflect.Map:
		if t.Key() == typeAny && t.Elem() == typeAny {
			return T.DynMap
		}
		return T.Map(TruOf(t.Key(), types), TruOf(t.Elem(), types))
	}
	return T.Dynamic
}
