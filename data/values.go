package data

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"
)

// Char16 is a UTF-16 code unit, encoded as the Char16 TDU.
type Char16 uint16

// NotModifiedType is the type of NotModified.
type NotModifiedType struct{}

// NotModified means "value unchanged" (C# NotModified).
var NotModified = NotModifiedType{}

func (NotModifiedType) String() string { return "NotModified" }

// ResourceID is a resource reference decoded without a connection to resolve it.
type ResourceID struct {
	Local bool
	ID    uint32
}

// ResourceLink is a textual link to a resource, e.g. "ep://host/path".
type ResourceLink string

// UUID is a 16-byte identifier, written as is.
type UUID [16]byte

func (u UUID) String() string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ParseUUID parses the canonical 8-4-4-4-12 hexadecimal form.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		return u, fmt.Errorf("esiur: invalid UUID %q", s)
	}
	copy(u[:], raw)
	return u, nil
}

// Int128 is a signed 128-bit integer in two's complement.
type Int128 struct{ Hi, Lo uint64 }

// UInt128 is an unsigned 128-bit integer.
type UInt128 struct{ Hi, Lo uint64 }

var two64 = new(big.Int).Lsh(big.NewInt(1), 64)
var two128 = new(big.Int).Lsh(big.NewInt(1), 128)

func splitBig(v *big.Int) (hi, lo uint64) {
	m := new(big.Int).Mod(v, two128)
	lo = new(big.Int).Mod(m, two64).Uint64()
	hi = new(big.Int).Rsh(m, 64).Uint64()
	return
}

// Int128FromBig converts v; it fails when v does not fit.
func Int128FromBig(v *big.Int) (Int128, error) {
	if v.BitLen() > 127 && !(v.Sign() < 0 && new(big.Int).Neg(v).Cmp(new(big.Int).Lsh(big.NewInt(1), 127)) == 0) {
		return Int128{}, fmt.Errorf("esiur: %s does not fit in Int128", v)
	}
	hi, lo := splitBig(v)
	return Int128{hi, lo}, nil
}

// UInt128FromBig converts v; it fails when v does not fit.
func UInt128FromBig(v *big.Int) (UInt128, error) {
	if v.Sign() < 0 || v.BitLen() > 128 {
		return UInt128{}, fmt.Errorf("esiur: %s does not fit in UInt128", v)
	}
	hi, lo := splitBig(v)
	return UInt128{hi, lo}, nil
}

// Big returns the value as a big.Int.
func (v UInt128) Big() *big.Int {
	b := new(big.Int).SetUint64(v.Hi)
	return b.Lsh(b, 64).Or(b, new(big.Int).SetUint64(v.Lo))
}

// Big returns the value as a big.Int.
func (v Int128) Big() *big.Int {
	b := UInt128(v).Big()
	if v.Hi>>63 == 1 {
		b.Sub(b, two128)
	}
	return b
}

func (v Int128) String() string  { return v.Big().String() }
func (v UInt128) String() string { return v.Big().String() }

// Decimal is a C# System.Decimal: a 96-bit mantissa scaled by 10^-Scale (0 to 28).
type Decimal struct {
	Lo, Mid, Hi uint32
	Scale       uint8
	Negative    bool
}

var two96 = new(big.Int).Lsh(big.NewInt(1), 96)

// NewDecimal builds mantissa * 10^-scale.
func NewDecimal(mantissa *big.Int, scale int) (Decimal, error) {
	m := new(big.Int).Abs(mantissa)
	if scale < 0 || scale > 28 || m.Cmp(two96) >= 0 {
		return Decimal{}, fmt.Errorf("esiur: value does not fit in Decimal128 (96-bit mantissa, scale <= 28)")
	}
	words := new(big.Int).Set(m)
	mask := big.NewInt(0xFFFFFFFF)
	lo := uint32(new(big.Int).And(words, mask).Uint64())
	mid := uint32(new(big.Int).And(new(big.Int).Rsh(words, 32), mask).Uint64())
	hi := uint32(new(big.Int).Rsh(words, 64).Uint64())
	return Decimal{Lo: lo, Mid: mid, Hi: hi, Scale: uint8(scale), Negative: mantissa.Sign() < 0}, nil
}

// ParseDecimal parses a decimal string such as "-12.50" or "1e3".
func ParseDecimal(s string) (Decimal, error) {
	text := strings.TrimSpace(s)
	exp := 0
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		if _, err := fmt.Sscan(text[i+1:], &exp); err != nil {
			return Decimal{}, fmt.Errorf("esiur: invalid decimal %q", s)
		}
		text = text[:i]
	}
	negative := strings.HasPrefix(text, "-")
	text = strings.TrimLeft(text, "+-")
	scale := 0
	if i := strings.IndexByte(text, '.'); i >= 0 {
		scale = len(text) - i - 1
		text = text[:i] + text[i+1:]
	}
	if text == "" {
		return Decimal{}, fmt.Errorf("esiur: invalid decimal %q", s)
	}
	m, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return Decimal{}, fmt.Errorf("esiur: invalid decimal %q", s)
	}
	scale -= exp
	if scale < 0 {
		m.Mul(m, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-scale)), nil))
		scale = 0
	}
	d, err := NewDecimal(m, scale)
	d.Negative = negative && m.Sign() != 0
	return d, err
}

// MustDecimal is ParseDecimal that panics on error.
func MustDecimal(s string) Decimal {
	d, err := ParseDecimal(s)
	if err != nil {
		panic(err)
	}
	return d
}

// Mantissa is the unsigned 96-bit mantissa.
func (d Decimal) Mantissa() *big.Int {
	m := new(big.Int).SetUint64(uint64(d.Hi))
	m.Lsh(m, 32).Or(m, big.NewInt(int64(d.Mid)))
	return m.Lsh(m, 32).Or(m, big.NewInt(int64(d.Lo)))
}

func (d Decimal) String() string {
	digits := d.Mantissa().String()
	scale := int(d.Scale)
	if scale > 0 {
		if len(digits) <= scale {
			digits = strings.Repeat("0", scale-len(digits)+1) + digits
		}
		digits = digits[:len(digits)-scale] + "." + digits[len(digits)-scale:]
	}
	if d.Negative && d.Mantissa().Sign() != 0 {
		return "-" + digits
	}
	return digits
}

// MapEntry is one key/value pair of a Map.
type MapEntry struct{ Key, Value any }

// Map is an ordered, self-describing map: it composes as the dynamic Map TDU and keeps the
// order entries were added in. Dynamic maps decode to it.
type Map []MapEntry

// Get returns the value of the first entry whose key equals key.
func (m Map) Get(key any) (any, bool) {
	for _, e := range m {
		if keysEqual(e.Key, key) {
			return e.Value, true
		}
	}
	return nil, false
}

// Set replaces the value of key, or appends a new entry.
func (m *Map) Set(key, value any) {
	for i, e := range *m {
		if keysEqual(e.Key, key) {
			(*m)[i].Value = value
			return
		}
	}
	*m = append(*m, MapEntry{key, value})
}

func keysEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == b
	}
	ta, tb := reflect.TypeOf(a), reflect.TypeOf(b)
	if ta.Comparable() && tb.Comparable() {
		if a == b {
			return true
		}
		if ia, ok := asInt(a); ok {
			if ib, ok := asInt(b); ok {
				return ia == ib
			}
		}
		return false
	}
	return reflect.DeepEqual(a, b)
}

// TypedList is a list whose element type is declared explicitly. Go slices of a concrete
// element type ([]int32, []string, ...) compose as typed lists on their own; use TypedList for
// element types Go cannot express (a TypedList<Dynamic>, a nullable element, ...).
type TypedList struct {
	Element Tru
	Values  any // a slice
}

// TypedMap is a map with declared key and value types, kept in order.
type TypedMap struct {
	Key, Value Tru
	Entries    Map
}

// TypedTuple is a tuple of two to seven elements with declared types. Typed tuples decode to it.
type TypedTuple struct {
	Types  []Tru
	Values []any
}
