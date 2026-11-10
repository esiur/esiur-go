package data

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"time"
)

// Composer encodes Go values into TDUs.
//
// Go <-> wire mapping for values:
//
//	nil, bool                    Null, True/False
//	int, int64                   narrowest of Int8/16/32/64
//	int8/16/32                   narrowest signed width up to the type's own
//	uint, uint8/16/32/64         narrowest unsigned width up to the type's own
//	float64                      Infinity for NaN/Inf, else the narrowest of Int8/16/32, Float32
//	                             (when exact) and Float64
//	float32                      Infinity, Int8/16 when whole, else Float32
//	string, []byte               String (UTF-8), RawData
//	time.Time                    DateTime (100 ns ticks since 0001-01-01 UTC)
//	UUID, Decimal, Int128, ...   UUID, Decimal128, Int128, UInt128, Char16
//	[]any, Map                   List, Map (self-describing)
//	[]T, map[K]V                 Typed (0x80) TypedList<T> / TypedMap<K,V> (keys sorted)
//	TypedList/TypedMap/TypedTuple  Typed with the declared metadata
//	Tru                          TRU (0x82)
//	IndexedStructure             Typed TypedMap<UInt8, Dynamic>, sparse
//	*TypeDefInfo                 TypeDef (0x81) wrapping its structure
//	registered record / enum     Typed with a TruTypeDef (needs Types)
//	ResourceID, Resources(v)     a local/remote resource reference
type Composer struct {
	// Types resolves registered records and enums.
	Types *TypeRegistry
	// Resources maps an object that stands for a resource to the reference to write.
	Resources func(value any) (ResourceID, bool)
	// NameOf, when set, writes TypeDef references as name hashes (signature mode).
	NameOf NameOf
}

// Compose encodes value as one self-describing TDU with no registry and no resource hook.
func Compose(value any) ([]byte, error) {
	var c Composer
	return c.Compose(value)
}

// MustCompose is Compose that panics on error.
func MustCompose(value any) []byte {
	b, err := Compose(value)
	if err != nil {
		panic(err)
	}
	return b
}

// Compose encodes value as one self-describing TDU.
func (c *Composer) Compose(value any) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(composeError); ok {
				err = e.error
				return
			}
			panic(r)
		}
	}()
	return c.tdu(value, 0).composed, nil
}

type composeError struct{ error }

func fail(format string, args ...any) {
	panic(composeError{fmt.Errorf("esiur: "+format, args...)})
}

// ctdu is a composed TDU plus what a parent needs to know about it.
type ctdu struct {
	composed      []byte
	identifier    byte
	metadata      Tru
	contentOffset int
}

// matchType reports whether other allows this one to be written as a TypeContinuation.
func (t *ctdu) matchType(other *ctdu) bool {
	if t.identifier != other.identifier || TduClass(t.identifier>>6) != TduTyped {
		return false
	}
	if t.identifier != IDTyped {
		return true
	}
	return t.metadata != nil && other.metadata != nil && t.metadata.Match(other.metadata)
}

func (t *ctdu) content() []byte { return t.composed[t.contentOffset:] }

func (c *Composer) truBytes(tru Tru) []byte {
	b, err := tru.appendTo(nil, c.NameOf)
	if err != nil {
		panic(composeError{err})
	}
	return b
}

func (c *Composer) make(id byte, payload []byte, metadata Tru) *ctdu {
	if TduClass(id>>6) == TduFixed {
		return &ctdu{append([]byte{id}, payload...), id, nil, 1}
	}
	if id != IDTyped {
		out := appendFramedHeader(make([]byte, 0, len(payload)+9), id, len(payload))
		h := len(out)
		return &ctdu{append(out, payload...), id, nil, h}
	}
	if metadata == nil {
		fail("metadata must be provided for typed TDUs")
	}
	meta := c.truBytes(metadata)
	out := appendFramedHeader(make([]byte, 0, len(meta)+len(payload)+9), id, len(meta)+len(payload))
	h := len(out) + len(meta)
	out = append(append(out, meta...), payload...)
	return &ctdu{out, id, metadata, h}
}

func fixed(id byte, payload []byte) *ctdu { return &ctdu{append([]byte{id}, payload...), id, nil, 1} }

func (c *Composer) asResource(value any) (ResourceID, bool) {
	switch r := value.(type) {
	case ResourceID:
		return r, true
	case *ResourceID:
		return *r, true
	}
	if c.Resources != nil && value != nil {
		return c.Resources(value)
	}
	return ResourceID{}, false
}

func composeResource(r ResourceID) *ctdu {
	switch {
	case r.ID <= 0xFF:
		id := IDRemoteResource8
		if r.Local {
			id = IDLocalResource8
		}
		return fixed(id, []byte{byte(r.ID)})
	case r.ID <= 0xFFFF:
		id := IDRemoteResource16
		if r.Local {
			id = IDLocalResource16
		}
		return fixed(id, binary.LittleEndian.AppendUint16(nil, uint16(r.ID)))
	}
	id := IDRemoteResource32
	if r.Local {
		id = IDLocalResource32
	}
	return fixed(id, binary.LittleEndian.AppendUint32(nil, r.ID))
}

// resourceList writes a non-empty list made only of resources as a ResourceList.
func (c *Composer) resourceList(items reflect.Value) *ctdu {
	if items.Len() == 0 {
		return nil
	}
	var payload []byte
	for i := 0; i < items.Len(); i++ {
		r, ok := c.asResource(items.Index(i).Interface())
		if !ok {
			return nil
		}
		payload = append(payload, composeResource(r).composed...)
	}
	return c.make(IDResourceList, payload, nil)
}

func (c *Composer) tdu(value any, depth int) *ctdu {
	if depth > DefaultMaximumValueDepth {
		panic(composeError{limitErr("Value nesting is too deep.")})
	}
	switch v := value.(type) {
	case nil:
		return fixed(IDNull, nil)
	case TypedList:
		return c.make(IDTyped, c.typedArray(reflect.ValueOf(v.Values), v.Element, depth), T.List(v.Element))
	case *TypedList:
		return c.tdu(*v, depth)
	case TypedMap:
		return c.typedMap(v.Key, v.Value, v.Entries, depth)
	case *TypedMap:
		return c.tdu(*v, depth)
	case TypedTuple:
		return c.typedTuple(v, depth)
	case *TypedTuple:
		return c.typedTuple(*v, depth)
	case Tru:
		return c.make(IDTru, c.truBytes(v), nil)
	case *TypeDefInfo:
		if v == nil {
			return fixed(IDNull, nil)
		}
		return c.make(IDTypeDef, c.tdu(ToIndexedMap(v), depth+1).composed, nil)
	case TypeDefInfo:
		return c.tdu(&v, depth)
	case IndexedStructure:
		s := indirectStruct(reflect.ValueOf(v))
		if !s.IsValid() {
			return fixed(IDNull, nil)
		}
		return c.tdu(toIndexedMap(s), depth+1)
	case Map:
		return c.array(mapItems(v), IDMap, depth)
	case *Map:
		return c.tdu(*v, depth)
	case []any:
		if r := c.resourceList(reflect.ValueOf(v)); r != nil {
			return r
		}
		return c.array(v, IDList, depth)
	case []byte:
		return c.make(IDRawData, v, nil)
	case reflect.Value:
		return c.tdu(v.Interface(), depth)
	}

	if c.Types != nil {
		if def, ok := c.Types.DefinitionOf(value); ok {
			return c.defined(value, def, depth)
		}
	}
	if r, ok := c.asResource(value); ok {
		return composeResource(r)
	}
	if out := composePlain(value); out != nil {
		return out
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return fixed(IDNull, nil)
		}
		return c.tdu(rv.Elem().Interface(), depth)
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return fixed(IDNull, nil)
		}
		et := rv.Type().Elem()
		if et.Kind() == reflect.Interface && c.Resources != nil {
			if r := c.resourceList(rv); r != nil {
				return r
			}
		}
		if isResourceType(et) {
			if r := c.resourceList(rv); r != nil {
				return r
			}
		}
		if et == typeAny {
			return c.array(sliceItems(rv), IDList, depth)
		}
		element := c.truOf(et)
		return c.make(IDTyped, c.typedArray(rv, element, depth), T.List(element))
	case reflect.Map:
		if rv.IsNil() {
			return fixed(IDNull, nil)
		}
		entries, _ := MapEntries(value)
		kt, vt := rv.Type().Key(), rv.Type().Elem()
		if kt == typeAny && vt == typeAny {
			return c.array(mapItems(entries), IDMap, depth)
		}
		return c.typedMap(c.truOf(kt), c.truOf(vt), entries, depth)
	case reflect.Bool:
		return composeBool(rv.Bool())
	case reflect.Int, reflect.Int64:
		return composeSigned(rv.Int(), 8)
	case reflect.Int8:
		return fixed(IDInt8, []byte{byte(rv.Int())})
	case reflect.Int16:
		return composeSigned(rv.Int(), 2)
	case reflect.Int32:
		return composeSigned(rv.Int(), 4)
	case reflect.Uint, reflect.Uint64:
		return composeUnsigned(rv.Uint(), 8)
	case reflect.Uint8:
		return composeUnsigned(rv.Uint(), 1)
	case reflect.Uint16:
		return composeUnsigned(rv.Uint(), 2)
	case reflect.Uint32:
		return composeUnsigned(rv.Uint(), 4)
	case reflect.Float32:
		return composeFloat32(float32(rv.Float()))
	case reflect.Float64:
		return composeFloat64(rv.Float())
	case reflect.String:
		return c.make(IDString, []byte(rv.String()), nil)
	}
	fail("cannot compose a value of type %T", value)
	return nil
}

func (c *Composer) truOf(t reflect.Type) Tru { return TruOf(t, c.Types) }

func sliceItems(rv reflect.Value) []any {
	out := make([]any, rv.Len())
	for i := range out {
		out[i] = rv.Index(i).Interface()
	}
	return out
}

func mapItems(m Map) []any {
	out := make([]any, 0, 2*len(m))
	for _, e := range m {
		out = append(out, e.Key, e.Value)
	}
	return out
}

// defined writes a registered record (each property in definition order) or enum (its constant
// index).
func (c *Composer) defined(value any, def *TypeDefinition, depth int) *ctdu {
	metadata := TruTypeDef{TypeID: def.ID}
	if def.Kind == KindEnum {
		index, ok := def.ConstantIndex(value)
		if !ok {
			return fixed(IDNull, nil) // not a constant of the enum: like esiur-ts
		}
		return c.make(IDTyped, []byte{byte(index)}, metadata)
	}
	rv := indirectStruct(reflect.ValueOf(value))
	if !rv.IsValid() {
		return fixed(IDNull, nil)
	}
	var payload []byte
	for _, prop := range def.Properties {
		var item any
		if prop.field != nil {
			item = rv.FieldByIndex(prop.field).Interface()
		} else if f, ok := fieldByWireName(rv.Type(), prop.Name); ok {
			item = rv.FieldByIndex(f.Index).Interface()
		} else {
			fail("record %s has no field for property %s", def.Name, prop.Name)
		}
		t := c.tdu(item, depth+1)
		if t.identifier == IDTyped && prop.ValueType != nil && t.metadata != nil && prop.ValueType.Match(t.metadata) {
			payload = append(payload, ComposeTdu(IDTypeOfTarget, t.content())...)
		} else {
			payload = append(payload, t.composed...)
		}
	}
	return c.make(IDTyped, payload, metadata)
}

// array writes a self-describing array. Consecutive Typed elements of one shape collapse their
// metadata into a TypeContinuation, as esiur-ts and esiur-dotnet do.
func (c *Composer) array(items []any, id byte, depth int) *ctdu {
	var payload []byte
	var previous *ctdu
	for _, item := range items {
		t := c.tdu(item, depth+1)
		if previous != nil && t.matchType(previous) {
			payload = append(payload, ComposeTdu(IDTypeContinuation, t.content())...)
		} else {
			payload = append(payload, t.composed...)
		}
		previous = t
	}
	return c.make(id, payload, nil)
}

func gvwieCodec(id TruIdentifier) (GroupCodec, int, bool) {
	switch id {
	case TruInt16:
		return GroupInt16, 2, true
	case TruInt32:
		return GroupInt32, 4, true
	case TruInt64:
		return GroupInt64, 8, true
	case TruUInt16:
		return GroupUInt16, 2, true
	case TruUInt32:
		return GroupUInt32, 4, true
	case TruUInt64:
		return GroupUInt64, 8, true
	}
	return GroupCodec{}, 0, false
}

func typedInt(value any, kind string, lo, hi int64) int64 {
	if ch, ok := value.(string); ok && kind == "Char" {
		r := []rune(ch)
		if len(r) == 1 {
			value = int64(r[0])
		}
	}
	i, ok := asInt(value)
	if !ok {
		fail("typed %s values must be integers; received %T", kind, value)
	}
	if i < lo || i > hi {
		fail("value %d does not fit in %s", i, kind)
	}
	return i
}

// typedElement keeps the collection's declared width for 8-bit and char elements.
func (c *Composer) typedElement(value any, element Tru, depth int) *ctdu {
	switch element.Identifier() {
	case TruUInt8:
		return fixed(IDUInt8, []byte{byte(typedInt(value, "UInt8", 0, 0xFF))})
	case TruInt8:
		return fixed(IDInt8, []byte{byte(typedInt(value, "Int8", -0x80, 0x7F))})
	case TruChar:
		return fixed(IDChar16, binary.LittleEndian.AppendUint16(nil, uint16(typedInt(value, "Char", 0, 0xFFFF))))
	}
	return c.tdu(value, depth+1)
}

func (c *Composer) typedArray(values reflect.Value, element Tru, depth int) []byte {
	for values.Kind() == reflect.Interface || values.Kind() == reflect.Pointer {
		values = values.Elem()
	}
	n := 0
	if values.IsValid() {
		if values.Kind() != reflect.Slice && values.Kind() != reflect.Array {
			fail("typed list values must be a slice, got %s", values.Type())
		}
		n = values.Len()
	}
	if codec, _, ok := gvwieCodec(element.Identifier()); ok && !element.Nullable() {
		var out []byte
		var err error
		if codec.Signed {
			ints := make([]int64, n)
			for i := range ints {
				v, ok := ToInt64(values.Index(i).Interface())
				if !ok {
					fail("typed %s values must be integers; received %T", element, values.Index(i).Interface())
				}
				ints[i] = v
			}
			out, err = codec.EncodeSigned(ints)
		} else {
			uints := make([]uint64, n)
			for i := range uints {
				v, ok := asUint(values.Index(i).Interface())
				if !ok {
					fail("typed %s values must be non-negative integers; received %v", element, values.Index(i).Interface())
				}
				uints[i] = v
			}
			out, err = codec.EncodeUnsigned(uints)
		}
		if err != nil {
			panic(composeError{err})
		}
		return out
	}

	var payload []byte
	var previous *ctdu
	for i := 0; i < n; i++ {
		t := c.typedElement(values.Index(i).Interface(), element, depth)
		switch {
		case t.identifier == IDTyped && t.metadata != nil && element.Match(t.metadata):
			// The element has exactly the declared type: its metadata is implied.
			payload = append(payload, ComposeTdu(IDTypeOfTarget, t.content())...)
		case previous != nil && t.matchType(previous):
			payload = append(payload, ComposeTdu(IDTypeContinuation, t.content())...)
		default:
			payload = append(payload, t.composed...)
		}
		previous = t
	}
	return payload
}

func (c *Composer) typedMap(key, value Tru, entries Map, depth int) *ctdu {
	keys := make([]any, len(entries))
	values := make([]any, len(entries))
	for i, e := range entries {
		keys[i], values[i] = e.Key, e.Value
	}
	payload := ComposeTdu(IDTypeOfTarget, c.typedArray(reflect.ValueOf(keys), key, depth))
	payload = append(payload, ComposeTdu(IDTypeOfTarget, c.typedArray(reflect.ValueOf(values), value, depth))...)
	return c.make(IDTyped, payload, T.Map(key, value))
}

func (c *Composer) typedTuple(v TypedTuple, depth int) *ctdu {
	id, err := TupleIdentifier(len(v.Types))
	if err != nil {
		panic(composeError{err})
	}
	if len(v.Types) != len(v.Values) {
		fail("tuple element-type count must match value count")
	}
	var payload []byte
	for i, target := range v.Types {
		t := c.tdu(v.Values[i], depth+1)
		if t.identifier == IDTyped && t.metadata != nil && target.Match(t.metadata) {
			payload = append(payload, ComposeTdu(IDTypeOfTarget, t.content())...)
		} else {
			payload = append(payload, t.composed...)
		}
	}
	return c.make(IDTyped, payload, TruComposite{Kind: id, SubTypes: v.Types})
}

func composeBool(b bool) *ctdu {
	if b {
		return fixed(IDTrue, nil)
	}
	return fixed(IDFalse, nil)
}

func signedFits(v int64, width int) bool {
	if width >= 8 {
		return true
	}
	lo, hi := -(int64(1) << (8*width - 1)), int64(1)<<(8*width-1)-1
	return v >= lo && v <= hi
}

func composeSigned(v int64, maxWidth int) *ctdu {
	switch {
	case signedFits(v, 1):
		return fixed(IDInt8, []byte{byte(v)})
	case signedFits(v, 2) && maxWidth >= 2:
		return fixed(IDInt16, binary.LittleEndian.AppendUint16(nil, uint16(v)))
	case signedFits(v, 4) && maxWidth >= 4:
		return fixed(IDInt32, binary.LittleEndian.AppendUint32(nil, uint32(v)))
	}
	return fixed(IDInt64, binary.LittleEndian.AppendUint64(nil, uint64(v)))
}

func composeUnsigned(v uint64, maxWidth int) *ctdu {
	switch {
	case v <= 0xFF:
		return fixed(IDUInt8, []byte{byte(v)})
	case v <= 0xFFFF && maxWidth >= 2:
		return fixed(IDUInt16, binary.LittleEndian.AppendUint16(nil, uint16(v)))
	case v <= 0xFFFF_FFFF && maxWidth >= 4:
		return fixed(IDUInt32, binary.LittleEndian.AppendUint32(nil, uint32(v)))
	}
	return fixed(IDUInt64, binary.LittleEndian.AppendUint64(nil, v))
}

func composeFloat64(v float64) *ctdu {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fixed(IDInfinity, nil)
	}
	if v == math.Trunc(v) && v >= math.MinInt32 && v <= math.MaxInt32 {
		return composeSigned(int64(v), 4)
	}
	if f := float32(v); float64(f) == v {
		return fixed(IDFloat32, binary.LittleEndian.AppendUint32(nil, math.Float32bits(f)))
	}
	return fixed(IDFloat64, binary.LittleEndian.AppendUint64(nil, math.Float64bits(v)))
}

func composeFloat32(v float32) *ctdu {
	f := float64(v)
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fixed(IDInfinity, nil)
	}
	if f == math.Trunc(f) && f >= math.MinInt16 && f <= math.MaxInt16 {
		return composeSigned(int64(f), 2)
	}
	return fixed(IDFloat32, binary.LittleEndian.AppendUint32(nil, math.Float32bits(v)))
}

const ticksAtUnixEpoch = 621_355_968_000_000_000

// TimeToTicks is t as .NET ticks (100 ns since 0001-01-01 UTC).
func TimeToTicks(t time.Time) int64 {
	sec := t.Unix()
	return sec*10_000_000 + int64(t.Nanosecond())/100 + ticksAtUnixEpoch
}

// TicksToTime is the UTC time of .NET ticks.
func TicksToTime(ticks int64) time.Time {
	rel := ticks - ticksAtUnixEpoch
	sec, rem := rel/10_000_000, rel%10_000_000
	if rem < 0 {
		sec--
		rem += 10_000_000
	}
	return time.Unix(sec, rem*100).UTC()
}

func composeDecimal(d Decimal) *ctdu {
	if d.Scale > 28 {
		fail("Decimal128 scale must be at most 28")
	}
	m := d.Mantissa()
	negative := d.Negative && m.Sign() != 0
	if d.Scale == 0 && m.IsInt64() {
		v := m.Int64()
		if negative {
			v = -v
		}
		return composeSigned(v, 8)
	}
	var flags uint32 = uint32(d.Scale) << 16
	if negative {
		flags |= 0x80000000
	}
	p := binary.LittleEndian.AppendUint32(nil, flags)
	p = binary.LittleEndian.AppendUint32(p, d.Hi)
	p = binary.LittleEndian.AppendUint32(p, d.Lo)
	p = binary.LittleEndian.AppendUint32(p, d.Mid)
	return fixed(IDDecimal128, p)
}

// composePlain handles the value types with a fixed wire form; nil means "not one of them".
func composePlain(value any) *ctdu {
	switch v := value.(type) {
	case NotModifiedType:
		return fixed(IDNotModified, nil)
	case bool:
		return composeBool(v)
	case int:
		return composeSigned(int64(v), 8)
	case int64:
		return composeSigned(v, 8)
	case int8:
		return fixed(IDInt8, []byte{byte(v)})
	case int16:
		return composeSigned(int64(v), 2)
	case int32:
		return composeSigned(int64(v), 4)
	case uint:
		return composeUnsigned(uint64(v), 8)
	case uint64:
		return composeUnsigned(v, 8)
	case uint8:
		return composeUnsigned(uint64(v), 1)
	case uint16:
		return composeUnsigned(uint64(v), 2)
	case uint32:
		return composeUnsigned(uint64(v), 4)
	case float64:
		return composeFloat64(v)
	case float32:
		return composeFloat32(v)
	case Char16:
		return fixed(IDChar16, binary.LittleEndian.AppendUint16(nil, uint16(v)))
	case Int128:
		p := binary.LittleEndian.AppendUint64(nil, v.Lo)
		return fixed(IDInt128, binary.LittleEndian.AppendUint64(p, v.Hi))
	case UInt128:
		p := binary.LittleEndian.AppendUint64(nil, v.Lo)
		return fixed(IDUInt128, binary.LittleEndian.AppendUint64(p, v.Hi))
	case *big.Int:
		if v.IsInt64() {
			return composeSigned(v.Int64(), 8)
		}
		if v.IsUint64() {
			return composeUnsigned(v.Uint64(), 8)
		}
		fail("integer exceeds the 64-bit range; convert it to Int128 or UInt128")
	case ResourceLink:
		return &ctdu{ComposeTdu(IDResourceLink, []byte(v)), IDResourceLink, nil, len(FramedHeader(IDResourceLink, len(v)))}
	case string:
		return &ctdu{ComposeTdu(IDString, []byte(v)), IDString, nil, len(FramedHeader(IDString, len(v)))}
	case time.Time:
		return fixed(IDDateTime, binary.LittleEndian.AppendUint64(nil, uint64(TimeToTicks(v))))
	case UUID:
		return fixed(IDUUID, v[:])
	case Decimal:
		return composeDecimal(v)
	}
	return nil
}
