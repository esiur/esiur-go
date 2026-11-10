package data

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// TruIdentifier names a type in a Tru header.
type TruIdentifier uint8

const (
	TruVoid     TruIdentifier = 0x00
	TruDynamic  TruIdentifier = 0x01
	TruBool     TruIdentifier = 0x02
	TruUInt8    TruIdentifier = 0x03
	TruInt8     TruIdentifier = 0x04
	TruChar     TruIdentifier = 0x05
	TruUInt16   TruIdentifier = 0x06
	TruInt16    TruIdentifier = 0x07
	TruUInt32   TruIdentifier = 0x08
	TruInt32    TruIdentifier = 0x09
	TruFloat32  TruIdentifier = 0x0A
	TruUInt64   TruIdentifier = 0x0B
	TruInt64    TruIdentifier = 0x0C
	TruFloat64  TruIdentifier = 0x0D
	TruDateTime TruIdentifier = 0x0E
	TruUInt128  TruIdentifier = 0x0F
	TruInt128   TruIdentifier = 0x10
	TruDecimal  TruIdentifier = 0x11
	TruString   TruIdentifier = 0x12
	TruRawData  TruIdentifier = 0x13
	TruResource TruIdentifier = 0x14
	TruRecord   TruIdentifier = 0x15
	TruList     TruIdentifier = 0x16
	TruMap      TruIdentifier = 0x17

	TruLocalType8   TruIdentifier = 0x40
	TruRemoteType8  TruIdentifier = 0x41
	TruLocalType16  TruIdentifier = 0x42
	TruRemoteType16 TruIdentifier = 0x43
	TruLocalType32  TruIdentifier = 0x44
	TruRemoteType32 TruIdentifier = 0x45
	TruLocalType64  TruIdentifier = 0x46
	TruRemoteType64 TruIdentifier = 0x47

	TruTypedList TruIdentifier = 0x48

	TruTuple2   TruIdentifier = 0x50
	TruTypedMap TruIdentifier = 0x51
	TruTuple3   TruIdentifier = 0x58
	TruTuple4   TruIdentifier = 0x60
	TruTuple5   TruIdentifier = 0x68
	TruTuple6   TruIdentifier = 0x70
	TruTuple7   TruIdentifier = 0x78
)

var truNames = map[TruIdentifier]string{
	TruVoid: "Void", TruDynamic: "Dynamic", TruBool: "Bool", TruUInt8: "UInt8", TruInt8: "Int8",
	TruChar: "Char", TruUInt16: "UInt16", TruInt16: "Int16", TruUInt32: "UInt32", TruInt32: "Int32",
	TruFloat32: "Float32", TruUInt64: "UInt64", TruInt64: "Int64", TruFloat64: "Float64",
	TruDateTime: "DateTime", TruUInt128: "UInt128", TruInt128: "Int128", TruDecimal: "Decimal",
	TruString: "String", TruRawData: "RawData", TruResource: "Resource", TruRecord: "Record",
	TruList: "List", TruMap: "Map", TruTypedList: "TypedList", TruTypedMap: "TypedMap",
	TruTuple2: "Tuple2", TruTuple3: "Tuple3", TruTuple4: "Tuple4", TruTuple5: "Tuple5",
	TruTuple6: "Tuple6", TruTuple7: "Tuple7",
}

func (id TruIdentifier) String() string {
	if name, ok := truNames[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%02x", uint8(id))
}

// IsTuple reports whether id is one of the Tuple2..Tuple7 identifiers.
func (id TruIdentifier) IsTuple() bool {
	switch id {
	case TruTuple2, TruTuple3, TruTuple4, TruTuple5, TruTuple6, TruTuple7:
		return true
	}
	return false
}

var tupleIdentifiers = map[int]TruIdentifier{
	2: TruTuple2, 3: TruTuple3, 4: TruTuple4, 5: TruTuple5, 6: TruTuple6, 7: TruTuple7,
}

// TupleIdentifier is the Tru identifier of a tuple with count elements (2 to 7).
func TupleIdentifier(count int) (TruIdentifier, error) {
	if id, ok := tupleIdentifiers[count]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("esiur: tuples must have between 2 and 7 elements, got %d", count)
}

// NameOf maps a TypeDef id to the name of the type it stands for (used by signatures).
type NameOf func(id uint64) (string, error)

// Tru (type representation unit) says how a value's type maps onto the wire. It is one header
// byte, (0x80 if nullable) | identifier. Identifiers below 0x40 are primitives (TruPrimitive).
// From 0x40, bits 3-5 give the number of sub-types that follow inline (TruComposite); a count
// of zero means a TypeDef reference whose id follows (TruTypeDef).
type Tru interface {
	Identifier() TruIdentifier
	Nullable() bool
	// Match reports the same type, ignoring nullability.
	Match(other Tru) bool
	// WithNullable returns a copy with the given nullability.
	WithNullable(nullable bool) Tru
	// Compose encodes the Tru.
	Compose() []byte
	String() string
	appendTo(b []byte, nameOf NameOf) ([]byte, error)
}

func truHeader(id TruIdentifier, nullable bool) byte {
	if nullable {
		return 0x80 | byte(id)
	}
	return byte(id)
}

func nullSuffix(nullable bool) string {
	if nullable {
		return "?"
	}
	return ""
}

// TruPrimitive is a type with no sub-types (Int32, String, Dynamic, ...).
type TruPrimitive struct {
	Kind       TruIdentifier
	IsNullable bool
}

func (t TruPrimitive) Identifier() TruIdentifier { return t.Kind }
func (t TruPrimitive) Nullable() bool            { return t.IsNullable }
func (t TruPrimitive) WithNullable(n bool) Tru   { t.IsNullable = n; return t }
func (t TruPrimitive) Compose() []byte           { return []byte{truHeader(t.Kind, t.IsNullable)} }
func (t TruPrimitive) String() string            { return t.Kind.String() + nullSuffix(t.IsNullable) }
func (t TruPrimitive) Match(o Tru) bool {
	p, ok := o.(TruPrimitive)
	return ok && p.Kind == t.Kind
}
func (t TruPrimitive) appendTo(b []byte, _ NameOf) ([]byte, error) {
	return append(b, truHeader(t.Kind, t.IsNullable)), nil
}

// TruComposite is a typed list, map or tuple, carrying its element types inline.
type TruComposite struct {
	Kind       TruIdentifier
	SubTypes   []Tru
	IsNullable bool
}

func (t TruComposite) Identifier() TruIdentifier { return t.Kind }
func (t TruComposite) Nullable() bool            { return t.IsNullable }
func (t TruComposite) WithNullable(n bool) Tru   { t.IsNullable = n; return t }
func (t TruComposite) Compose() []byte           { b, _ := t.appendTo(nil, nil); return b }
func (t TruComposite) String() string {
	parts := make([]string, len(t.SubTypes))
	for i, s := range t.SubTypes {
		parts[i] = s.String()
	}
	return t.Kind.String() + "<" + strings.Join(parts, ",") + ">" + nullSuffix(t.IsNullable)
}
func (t TruComposite) Match(o Tru) bool {
	c, ok := o.(TruComposite)
	if !ok || c.Kind != t.Kind || len(c.SubTypes) != len(t.SubTypes) {
		return false
	}
	for i := range t.SubTypes {
		if !t.SubTypes[i].Match(c.SubTypes[i]) {
			return false
		}
	}
	return true
}
func (t TruComposite) appendTo(b []byte, nameOf NameOf) ([]byte, error) {
	b = append(b, truHeader(t.Kind, t.IsNullable))
	var err error
	for _, s := range t.SubTypes {
		if b, err = s.appendTo(b, nameOf); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// TruTypeDef is a reference to a registered record, enum or resource type, by id.
type TruTypeDef struct {
	TypeID     uint64
	IsNullable bool
	Remote     bool
}

func typeIDWidth(id uint64) int {
	switch {
	case id <= 0xFF:
		return 1
	case id <= 0xFFFF:
		return 2
	case id <= 0xFFFF_FFFF:
		return 4
	}
	return 8
}

var localByWidth = map[int]TruIdentifier{1: TruLocalType8, 2: TruLocalType16, 4: TruLocalType32, 8: TruLocalType64}
var remoteByWidth = map[int]TruIdentifier{1: TruRemoteType8, 2: TruRemoteType16, 4: TruRemoteType32, 8: TruRemoteType64}

func (t TruTypeDef) Identifier() TruIdentifier {
	if t.Remote {
		return remoteByWidth[typeIDWidth(t.TypeID)]
	}
	return localByWidth[typeIDWidth(t.TypeID)]
}
func (t TruTypeDef) Nullable() bool          { return t.IsNullable }
func (t TruTypeDef) WithNullable(n bool) Tru { t.IsNullable = n; return t }
func (t TruTypeDef) Compose() []byte         { b, _ := t.appendTo(nil, nil); return b }
func (t TruTypeDef) Match(o Tru) bool {
	d, ok := o.(TruTypeDef)
	return ok && d.TypeID == t.TypeID
}
func (t TruTypeDef) String() string {
	prefix := ""
	if t.Remote {
		prefix = "remote:"
	}
	return fmt.Sprintf("%stype#%d%s", prefix, t.TypeID, nullSuffix(t.IsNullable))
}
func (t TruTypeDef) appendTo(b []byte, nameOf NameOf) ([]byte, error) {
	if nameOf != nil {
		// Signature mode: the hash of the referenced name, written with the widest identifier,
		// so the result never depends on a TypeDef id or its width.
		name, err := nameOf(t.TypeID)
		if err != nil {
			return nil, err
		}
		b = append(b, truHeader(TruLocalType64, t.IsNullable))
		return binary.LittleEndian.AppendUint64(b, Name64(name)), nil
	}
	width := typeIDWidth(t.TypeID)
	b = append(b, truHeader(t.Identifier(), t.IsNullable))
	for i := 0; i < width; i++ {
		b = append(b, byte(t.TypeID>>(8*i)))
	}
	return b, nil
}

func typeDefIDWidth(id TruIdentifier) (width int, remote bool, ok bool) {
	switch id {
	case TruLocalType8:
		return 1, false, true
	case TruRemoteType8:
		return 1, true, true
	case TruLocalType16:
		return 2, false, true
	case TruRemoteType16:
		return 2, true, true
	case TruLocalType32:
		return 4, false, true
	case TruRemoteType32:
		return 4, true, true
	case TruLocalType64:
		return 8, false, true
	case TruRemoteType64:
		return 8, true, true
	}
	return 0, false, false
}

// ParseTru parses a Tru at offset (bounded by ends); it returns the Tru and the bytes consumed.
func ParseTru(data []byte, offset, ends, maximumDepth int) (Tru, int, error) {
	return parseTru(data, offset, ends, 1, maximumDepth)
}

func parseTru(data []byte, offset, ends, depth, maxDepth int) (Tru, int, error) {
	if err := ensureTypeMetadataDepth(depth, maxDepth); err != nil {
		return nil, 0, err
	}
	if offset >= ends {
		return nil, 0, parseErr("Truncated TRU.")
	}
	start := offset
	header := data[offset]
	offset++
	nullable := header&0x80 != 0
	id := TruIdentifier(header & 0x7F)

	if header&0x40 == 0 {
		return TruPrimitive{Kind: id, IsNullable: nullable}, 1, nil
	}

	subCount := int((header >> 3) & 0x7)
	if subCount == 0 {
		width, remote, ok := typeDefIDWidth(id)
		if !ok {
			return nil, 0, parseErr("Invalid TRU TypeDef identifier 0x%02x.", uint8(id))
		}
		if ends-offset < width {
			return nil, 0, parseErr("Truncated TRU TypeDef id.")
		}
		var typeID uint64
		for i := 0; i < width; i++ {
			typeID |= uint64(data[offset+i]) << (8 * i)
		}
		return TruTypeDef{TypeID: typeID, IsNullable: nullable, Remote: remote}, 1 + width, nil
	}

	subs := make([]Tru, 0, subCount)
	for i := 0; i < subCount; i++ {
		sub, size, err := parseTru(data, offset, ends, depth+1, maxDepth)
		if err != nil {
			return nil, 0, err
		}
		subs = append(subs, sub)
		offset += size
	}
	return TruComposite{Kind: id, SubTypes: subs, IsNullable: nullable}, offset - start, nil
}

// TruTypes is the namespace of ready-made Trus exposed as T: T.I32, T.List(T.String), ...
type TruTypes struct {
	Void, Dynamic, Bool, Char, U8, I8, U16, I16, U32, I32, U64, I64, U128, I128,
	F32, F64, Decimal, String, RawData, DateTime, Resource, Record, DynList, DynMap TruPrimitive
}

// List is a typed list of element.
func (TruTypes) List(element Tru) TruComposite {
	return TruComposite{Kind: TruTypedList, SubTypes: []Tru{element}}
}

// Map is a typed map from key to value.
func (TruTypes) Map(key, value Tru) TruComposite {
	return TruComposite{Kind: TruTypedMap, SubTypes: []Tru{key, value}}
}

// Tuple is a typed tuple of two to seven elements; it panics on any other count.
func (TruTypes) Tuple(subTypes ...Tru) TruComposite {
	id, err := TupleIdentifier(len(subTypes))
	if err != nil {
		panic(err)
	}
	return TruComposite{Kind: id, SubTypes: append([]Tru(nil), subTypes...)}
}

// Nullable returns t marked nullable.
func (TruTypes) Nullable(t Tru) Tru { return t.WithNullable(true) }

// TypeDef references a registered type by id.
func (TruTypes) TypeDef(id uint64) TruTypeDef { return TruTypeDef{TypeID: id} }

func prim(id TruIdentifier) TruPrimitive { return TruPrimitive{Kind: id} }

// T holds the ready-made Trus.
var T = TruTypes{
	Void: prim(TruVoid), Dynamic: prim(TruDynamic), Bool: prim(TruBool), Char: prim(TruChar),
	U8: prim(TruUInt8), I8: prim(TruInt8), U16: prim(TruUInt16), I16: prim(TruInt16),
	U32: prim(TruUInt32), I32: prim(TruInt32), U64: prim(TruUInt64), I64: prim(TruInt64),
	U128: prim(TruUInt128), I128: prim(TruInt128), F32: prim(TruFloat32), F64: prim(TruFloat64),
	Decimal: prim(TruDecimal), String: prim(TruString), RawData: prim(TruRawData),
	DateTime: prim(TruDateTime), Resource: prim(TruResource), Record: prim(TruRecord),
	DynList: prim(TruList), DynMap: prim(TruMap),
}
