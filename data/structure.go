package data

import (
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// IndexedStructure is a schema-less type whose members travel by byte index (esiur-ts
// IndexedStructure). It composes as a sparse TypedMap<UInt8, Dynamic>: nil members are omitted,
// and indices the receiver does not know are ignored, so either side can add members without
// breaking the other.
//
// Declare one by embedding Indexed and tagging members with their index:
//
//	type Point struct {
//		data.Indexed
//		X     int32   `idx:"0"`
//		Label *string `idx:"1"`
//	}
//
// The Go field type sets the wire width of numbers. Slices and maps travel as dynamic List and
// Map values unless the tag adds ",typed" (then []string is a TypedList<String>, ...).
type IndexedStructure interface{ esiurIndexed() }

// Indexed is embedded in a struct to make it an IndexedStructure.
type Indexed struct{}

func (Indexed) esiurIndexed() {}

type indexedMember struct {
	index uint8
	field []int
	name  string
	typed bool
}

var indexedCache sync.Map // reflect.Type -> []indexedMember

func indexedMembers(t reflect.Type) []indexedMember {
	if cached, ok := indexedCache.Load(t); ok {
		return cached.([]indexedMember)
	}
	var members []indexedMember
	seen := map[uint8]string{}
	for _, f := range reflect.VisibleFields(t) {
		tag, ok := f.Tag.Lookup("idx")
		if !ok || !f.IsExported() {
			continue
		}
		parts := strings.Split(tag, ",")
		n, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 0, 8)
		if err != nil {
			panic("esiur: invalid idx tag on " + t.String() + "." + f.Name)
		}
		index := uint8(n)
		if other, dup := seen[index]; dup {
			panic("esiur: structure index " + parts[0] + " used by both " + other + " and " + f.Name + " on " + t.String())
		}
		seen[index] = f.Name
		m := indexedMember{index: index, field: f.Index, name: f.Name}
		for _, opt := range parts[1:] {
			if strings.TrimSpace(opt) == "typed" {
				m.typed = true
			}
		}
		members = append(members, m)
	}
	// Ordered by wire index.
	for i := 1; i < len(members); i++ {
		for j := i; j > 0 && members[j].index < members[j-1].index; j-- {
			members[j], members[j-1] = members[j-1], members[j]
		}
	}
	indexedCache.Store(t, members)
	return members
}

func indirectStruct(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

// ToIndexedMap is the sparse TypedMap<UInt8, Dynamic> an indexed structure composes as.
func ToIndexedMap(value IndexedStructure) TypedMap {
	return toIndexedMap(indirectStruct(reflect.ValueOf(value)))
}

func toIndexedMap(v reflect.Value) TypedMap {
	out := TypedMap{Key: T.U8, Value: T.Dynamic, Entries: Map{}}
	for _, m := range indexedMembers(v.Type()) {
		fv := v.FieldByIndex(m.field)
		if isNilValue(fv) {
			continue
		}
		var item any
		if m.typed {
			item = fv.Interface()
		} else {
			item = prepareIndexed(fv)
		}
		out.Entries = append(out.Entries, MapEntry{m.index, item})
	}
	return out
}

func isNilValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// prepareIndexed turns a member value into what it composes as: nested structures become
// indexed maps, slices dynamic lists and maps dynamic maps.
func prepareIndexed(v reflect.Value) any {
	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		if _, isTru := v.Interface().(Tru); isTru {
			return v.Interface()
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		if v.Type().Implements(typeIndexed) && v.Elem().Kind() == reflect.Struct {
			return toIndexedMap(v.Elem())
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		if v.Type().Implements(typeIndexed) {
			return toIndexedMap(v)
		}
	case reflect.Slice:
		if v.Type() == typeBytes {
			return v.Interface()
		}
		items := make([]any, v.Len())
		for i := range items {
			items[i] = prepareIndexed(v.Index(i))
		}
		return items
	case reflect.Map:
		entries, _ := MapEntries(v.Interface())
		out := make(Map, len(entries))
		for i, e := range entries {
			out[i] = MapEntry{prepareIndexed(reflect.ValueOf(e.Key)), prepareIndexed(reflect.ValueOf(e.Value))}
		}
		return out
	}
	if !v.IsValid() {
		return nil
	}
	return v.Interface()
}

// FromIndexedMap fills target (a pointer to an indexed structure) from a decoded indexed-map
// payload. Members missing from the map keep their current value; unknown indices are ignored.
func FromIndexedMap(value any, target IndexedStructure) error {
	rv := reflect.ValueOf(target)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return parseErr("FromIndexedMap needs a non-nil pointer.")
	}
	out, err := fromIndexedMap(value, rv.Elem().Type())
	if err != nil {
		return err
	}
	rv.Elem().Set(out)
	return nil
}

func fromIndexedMap(value any, t reflect.Type) (reflect.Value, error) {
	entries, ok := MapEntries(value)
	if !ok {
		return reflect.Value{}, parseErr("%s must decode from a map, received %T.", t.Name(), value)
	}
	byIndex := make(map[int64]any, len(entries))
	for _, e := range entries {
		if k, ok := asInt(e.Key); ok {
			byIndex[k] = e.Value
		}
	}
	out := reflect.New(t).Elem()
	for _, m := range indexedMembers(t) {
		item, ok := byIndex[int64(m.index)]
		if !ok || item == nil {
			continue
		}
		field := out.FieldByIndex(m.field)
		v, err := Convert(item, field.Type())
		if err != nil {
			return reflect.Value{}, parseErr("%s.%s must be %s, received %T.", t.Name(), m.name, field.Type(), item)
		}
		field.Set(v)
	}
	return out, nil
}
