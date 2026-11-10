package data

import (
	"encoding/binary"
	"math"
	"reflect"
	"unicode/utf8"
)

// Parser decodes TDUs into Go values.
//
// Fixed-width numbers decode to the Go type of their wire width (int8 ... uint64, float32,
// float64), Char16 to Char16, DateTime to time.Time (UTC), resource references to ResourceID.
// Dynamic lists decode to []any and maps to Map. Typed lists decode to a slice of the element's
// Go type ([]int32, []string, [][]int32, ...; []any when the element is nullable or dynamic),
// typed maps to a Go map (or Map when keys are dynamic), tuples to TypedTuple, TypeDefs to
// *TypeDefInfo and TRUs to Tru.
type Parser struct {
	Limits Limits
	// Types resolves registered records and enums.
	Types *TypeRegistry
}

// NewParser returns a parser with the default limits.
func NewParser(types *TypeRegistry) *Parser {
	return &Parser{Limits: DefaultLimits(), Types: types}
}

// Parse decodes one value at the start of data with the default limits.
func Parse(data []byte) (any, error) {
	v, _, err := NewParser(nil).ParseAt(data, 0)
	return v, err
}

// Parse decodes the value at the start of data.
func (p *Parser) Parse(data []byte) (any, error) {
	v, _, err := p.ParseAt(data, 0)
	return v, err
}

// ParseAt decodes one value at offset; it returns the value and the bytes consumed.
func (p *Parser) ParseAt(data []byte, offset int) (any, int, error) {
	tdu, err := ParseTdu(data, offset, len(data), p.Limits)
	if err != nil {
		return nil, 0, err
	}
	if !tdu.Valid() {
		return nil, 0, parseErr("Incomplete value.")
	}
	v, err := p.decode(&tdu, 0)
	if err != nil {
		return nil, 0, err
	}
	return v, tdu.TotalLength, nil
}

// Decode decodes an already measured TDU.
func (p *Parser) Decode(tdu *ParsedTdu) (any, error) {
	if tdu.Metadata == nil && tdu.Identifier == IDTyped {
		// A measured (not parsed) Typed TDU: parse it again to read its metadata.
		re, err := ParseTdu(tdu.Data, tdu.TduOffset, tdu.TduOffset+tdu.TotalLength, p.Limits)
		if err != nil {
			return nil, err
		}
		tdu = &re
	}
	return p.decode(tdu, 0)
}

func (p *Parser) child(data []byte, offset, ends int) (*ParsedTdu, error) {
	tdu, err := ParseTdu(data, offset, ends, p.Limits)
	if err != nil {
		return nil, err
	}
	if !tdu.Valid() {
		return nil, parseErr("Truncated value inside a collection.")
	}
	return &tdu, nil
}

// inherit gives a TypeContinuation the type of the element before it.
func inherit(current, previous *ParsedTdu) {
	current.Class = previous.Class
	current.Identifier = previous.Identifier
	current.Index = previous.Index
	current.Exponent = previous.Exponent
	current.Metadata = previous.Metadata
}

// implied makes a TypeOfTarget element a Typed value whose metadata is the declared type.
func implied(current *ParsedTdu, metadata Tru) {
	current.Class = TduTyped
	current.Identifier = IDTyped
	current.Index = 0
	current.Metadata = metadata
}

func (p *Parser) fixed(t *ParsedTdu) (any, error) {
	b := t.Payload()
	switch t.Identifier {
	case IDNull:
		return nil, nil
	case IDFalse:
		return false, nil
	case IDTrue:
		return true, nil
	case IDNotModified:
		return NotModified, nil
	case IDInfinity:
		return math.Inf(1), nil
	case IDUInt8, IDChar8:
		return b[0], nil
	case IDInt8:
		return int8(b[0]), nil
	case IDLocalResource8, IDRemoteResource8:
		return ResourceID{Local: t.Identifier == IDLocalResource8, ID: uint32(b[0])}, nil
	case IDUInt16:
		return le16(b), nil
	case IDInt16:
		return int16(le16(b)), nil
	case IDChar16:
		return Char16(le16(b)), nil
	case IDLocalResource16, IDRemoteResource16:
		return ResourceID{Local: t.Identifier == IDLocalResource16, ID: uint32(le16(b))}, nil
	case IDUInt32:
		return le32(b), nil
	case IDInt32:
		return int32(le32(b)), nil
	case IDFloat32:
		return math.Float32frombits(le32(b)), nil
	case IDLocalResource32, IDRemoteResource32:
		return ResourceID{Local: t.Identifier == IDLocalResource32, ID: le32(b)}, nil
	case IDUInt64:
		return le64(b), nil
	case IDInt64:
		return int64(le64(b)), nil
	case IDFloat64:
		return math.Float64frombits(le64(b)), nil
	case IDDateTime:
		return TicksToTime(int64(le64(b))), nil
	case IDUInt128:
		return UInt128{Lo: le64(b), Hi: le64(b[8:])}, nil
	case IDInt128:
		return Int128{Lo: le64(b), Hi: le64(b[8:])}, nil
	case IDDecimal128:
		flags := le32(b)
		scale := (flags >> 16) & 0xFF
		if scale > 28 {
			return nil, parseErr("Decimal128 scale is out of range.")
		}
		d := Decimal{Hi: le32(b[4:]), Lo: le32(b[8:]), Mid: le32(b[12:]), Scale: uint8(scale)}
		d.Negative = flags&0x80000000 != 0 && d.Mantissa().Sign() != 0
		return d, nil
	case IDUUID:
		var u UUID
		copy(u[:], b)
		return u, nil
	}
	return nil, parseErr("Unsupported fixed TDU 0x%02x.", t.Identifier)
}

func utf8String(t *ParsedTdu) (string, error) {
	b := t.Payload()
	if !utf8.Valid(b) {
		return "", parseErr("String is not valid UTF-8.")
	}
	return string(b), nil
}

func (p *Parser) array(t *ParsedTdu, depth int) ([]any, error) {
	items := []any{}
	offset, ends := t.PayloadOffset, t.PayloadOffset+t.PayloadLength
	var previous *ParsedTdu
	for offset < ends {
		current, err := p.child(t.Data, offset, ends)
		if err != nil {
			return nil, err
		}
		if current.Identifier == IDTypeContinuation && previous != nil {
			inherit(current, previous)
		}
		v, err := p.decode(current, depth+1)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
		if err := ensureCollectionCount(len(items), p.Limits.MaximumCollectionItems); err != nil {
			return nil, err
		}
		offset += current.TotalLength
		previous = current
	}
	return items, nil
}

func (p *Parser) typedArray(t *ParsedTdu, element Tru, depth int) (reflect.Value, error) {
	goType := GoTypeOf(element, p.Types)
	sliceType := reflect.SliceOf(goType)
	if codec, size, ok := gvwieCodec(element.Identifier()); ok && !element.Nullable() {
		alloc := p.Limits.MaximumAllocationSize
		if err := ensureAllocation(t.PayloadLength*size, alloc, "typed array"); err != nil {
			return reflect.Value{}, err
		}
		raw, err := codec.Decode(t.Payload(), func(count int) error {
			if err := ensureCollectionCount(count, p.Limits.MaximumCollectionItems); err != nil {
				return err
			}
			return ensureAllocation(count*size, alloc, "typed array")
		})
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.MakeSlice(sliceType, len(raw), len(raw))
		for i, v := range raw {
			if codec.Signed {
				out.Index(i).SetInt(int64(v))
			} else {
				out.Index(i).SetUint(v)
			}
		}
		return out, nil
	}

	out := reflect.MakeSlice(sliceType, 0, 0)
	offset, ends := t.PayloadOffset, t.PayloadOffset+t.PayloadLength
	var previous *ParsedTdu
	for offset < ends {
		current, err := p.child(t.Data, offset, ends)
		if err != nil {
			return reflect.Value{}, err
		}
		if current.Identifier == IDTypeContinuation && previous != nil {
			inherit(current, previous)
		} else if current.Identifier == IDTypeOfTarget {
			implied(current, element)
		}
		v, err := p.decode(current, depth+1)
		if err != nil {
			return reflect.Value{}, err
		}
		cv, err := Convert(v, goType)
		if err != nil {
			return reflect.Value{}, err
		}
		out = reflect.Append(out, cv)
		if err := ensureCollectionCount(out.Len(), p.Limits.MaximumCollectionItems); err != nil {
			return reflect.Value{}, err
		}
		offset += current.TotalLength
		previous = current
	}
	return out, nil
}

func (p *Parser) typedMap(t *ParsedTdu, keyType, valueType Tru, depth int) (any, error) {
	ends := t.PayloadOffset + t.PayloadLength
	keysTdu, err := p.child(t.Data, t.PayloadOffset, ends)
	if err != nil {
		return nil, err
	}
	valuesTdu, err := p.child(t.Data, keysTdu.PayloadOffset+keysTdu.PayloadLength, ends)
	if err != nil {
		return nil, err
	}
	if keysTdu.Identifier != IDTypeOfTarget || valuesTdu.Identifier != IDTypeOfTarget {
		return nil, parseErr("A typed map holds a keys array followed by a values array.")
	}
	keys, err := p.typedArray(keysTdu, keyType, depth+1)
	if err != nil {
		return nil, err
	}
	values, err := p.typedArray(valuesTdu, valueType, depth+1)
	if err != nil {
		return nil, err
	}
	if keys.Len() != values.Len() {
		return nil, parseErr("A typed map has a different number of keys and values.")
	}
	mapType := GoTypeOf(T.Map(keyType, valueType), p.Types)
	if mapType == typeMap {
		out := make(Map, keys.Len())
		for i := range out {
			out[i] = MapEntry{keys.Index(i).Interface(), values.Index(i).Interface()}
		}
		return out, nil
	}
	out := reflect.MakeMapWithSize(mapType, keys.Len())
	for i := 0; i < keys.Len(); i++ {
		out.SetMapIndex(keys.Index(i), values.Index(i))
	}
	return out.Interface(), nil
}

func (p *Parser) typedTuple(t *ParsedTdu, subTypes []Tru, depth int) (any, error) {
	out := TypedTuple{Types: subTypes, Values: make([]any, 0, len(subTypes))}
	offset, ends := t.PayloadOffset, t.PayloadOffset+t.PayloadLength
	for _, sub := range subTypes {
		current, err := p.child(t.Data, offset, ends)
		if err != nil {
			return nil, err
		}
		if current.Identifier == IDTypeOfTarget {
			implied(current, sub)
		}
		v, err := p.decode(current, depth+1)
		if err != nil {
			return nil, err
		}
		cv, err := Convert(v, GoTypeOf(sub, p.Types))
		if err != nil {
			return nil, err
		}
		out.Values = append(out.Values, cv.Interface())
		offset += current.TotalLength
	}
	return out, nil
}

func (p *Parser) typed(t *ParsedTdu, depth int) (any, error) {
	switch tru := t.Metadata.(type) {
	case TruComposite:
		switch {
		case tru.Kind == TruTypedList:
			v, err := p.typedArray(t, tru.SubTypes[0], depth)
			if err != nil {
				return nil, err
			}
			return v.Interface(), nil
		case tru.Kind == TruTypedMap:
			return p.typedMap(t, tru.SubTypes[0], tru.SubTypes[1], depth)
		case tru.Kind.IsTuple():
			return p.typedTuple(t, tru.SubTypes, depth)
		}
		return nil, parseErr("Unsupported typed value with TRU identifier 0x%02x.", uint8(tru.Kind))
	case TruTypeDef:
		return p.defined(t, tru, depth)
	}
	return nil, parseErr("Unknown TRU %v.", t.Metadata)
}

func (p *Parser) defined(t *ParsedTdu, tru TruTypeDef, depth int) (any, error) {
	if tru.Remote {
		return nil, parseErr("Remote type definitions require a connection.")
	}
	if p.Types == nil {
		return nil, parseErr("TypeDef %d cannot be decoded without a TypeRegistry.", tru.TypeID)
	}
	def, ok := p.Types.ByID(tru.TypeID)
	if !ok {
		return nil, parseErr("TypeDef %d is not registered.", tru.TypeID)
	}
	switch def.Kind {
	case KindEnum:
		if t.PayloadLength != 1 {
			return nil, parseErr("An enum value is a single constant index.")
		}
		return def.ConstantValue(int(t.Data[t.PayloadOffset]))
	case KindRecord:
		return p.record(t, def, depth)
	}
	return nil, parseErr("Typed resource values need the resource layer.")
}

func (p *Parser) record(t *ParsedTdu, def *TypeDefinition, depth int) (any, error) {
	if err := ensureCollectionCount(len(def.Properties), p.Limits.MaximumCollectionItems); err != nil {
		return nil, err
	}
	offset, ends := t.PayloadOffset, t.PayloadOffset+t.PayloadLength
	values := make([]any, 0, len(def.Properties))
	var previous *ParsedTdu
	for _, prop := range def.Properties {
		current, err := p.child(t.Data, offset, ends)
		if err != nil {
			return nil, err
		}
		if current.Identifier == IDTypeContinuation && previous != nil {
			inherit(current, previous)
		} else if current.Identifier == IDTypeOfTarget {
			if prop.ValueType == nil {
				return nil, parseErr("Property '%s' has no declared type for an implied value.", prop.Name)
			}
			implied(current, prop.ValueType)
		}
		v, err := p.decode(current, depth+1)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
		offset += current.TotalLength
		previous = current
	}
	if offset != ends {
		return nil, parseErr("Record '%s' has data after its last property.", def.Name)
	}
	if def.GoType == nil {
		out := make(map[string]any, len(values))
		for i, prop := range def.Properties {
			out[prop.Name] = values[i]
		}
		return out, nil
	}
	out := reflect.New(def.GoType).Elem()
	for i, prop := range def.Properties {
		var field reflect.Value
		if prop.field != nil {
			field = out.FieldByIndex(prop.field)
		} else if f, ok := fieldByWireName(def.GoType, prop.Name); ok {
			field = out.FieldByIndex(f.Index)
		} else {
			continue
		}
		cv, err := Convert(values[i], field.Type())
		if err != nil {
			return nil, err
		}
		field.Set(cv)
	}
	return out.Interface(), nil
}

func (p *Parser) typeDef(t *ParsedTdu, depth int) (any, error) {
	end := t.PayloadOffset + t.PayloadLength
	inner, err := ParseTdu(t.Data, t.PayloadOffset, end, p.Limits)
	if err != nil {
		return nil, err
	}
	if !inner.Valid() || inner.TotalLength != t.PayloadLength {
		return nil, parseErr("The TypeDef payload contains trailing or incomplete data.")
	}
	v, err := p.decode(&inner, depth+1)
	if err != nil {
		return nil, err
	}
	return TypeDefInfoFromMap(v)
}

func (p *Parser) tru(t *ParsedTdu) (any, error) {
	end := t.PayloadOffset + t.PayloadLength
	tru, size, err := ParseTru(t.Data, t.PayloadOffset, end, p.Limits.MaximumTypeMetadataDepth)
	if err != nil {
		return nil, err
	}
	if size != t.PayloadLength {
		return nil, parseErr("The TRU payload contains trailing or incomplete data.")
	}
	return tru, nil
}

func (p *Parser) decode(t *ParsedTdu, depth int) (any, error) {
	if depth > DefaultMaximumValueDepth {
		return nil, limitErr("Value nesting is too deep.")
	}
	switch t.Class {
	case TduFixed:
		return p.fixed(t)
	case TduDynamic:
		switch t.Identifier {
		case IDRawData:
			return append([]byte{}, t.Payload()...), nil
		case IDString:
			return utf8String(t)
		case IDResourceLink:
			s, err := utf8String(t)
			return ResourceLink(s), err
		case IDList, IDResourceList, IDRecordList, IDMapList:
			return p.array(t, depth)
		case IDMap:
			flat, err := p.array(t, depth)
			if err != nil {
				return nil, err
			}
			if len(flat)%2 != 0 {
				return nil, parseErr("Map has a key without a value.")
			}
			out := make(Map, 0, len(flat)/2)
			for i := 0; i < len(flat); i += 2 {
				out = append(out, MapEntry{flat[i], flat[i+1]})
			}
			return out, nil
		}
		return nil, parseErr("Unsupported dynamic TDU 0x%02x.", t.Identifier)
	case TduTyped:
		switch t.Index {
		case 0:
			return p.typed(t, depth)
		case 1:
			return p.typeDef(t, depth)
		case 2:
			return p.tru(t)
		}
		return nil, parseErr("Unsupported typed TDU 0x%02x.", t.Identifier)
	}
	return nil, parseErr("Unsupported TDU class.")
}

var _ = binary.LittleEndian
