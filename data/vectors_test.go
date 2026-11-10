package data

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"
)

// Differential test: Go must compose exactly the bytes esiur-ts composes. The fixture is shared
// with esiur-python (tools/gen-ts-vectors.mjs there); its "python" field is ignored here.

type vector struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func rangeInts[V int16 | int32 | int64 | uint16 | uint32 | uint64](n int, f func(i int) V) []V {
	out := make([]V, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

var two40 = uint64(1) << 40

var goVectors = map[string]any{
	"null":                         nil,
	"true":                         true,
	"int_300":                      300,
	"int_neg_70000":                -70000,
	"int_int32_max":                2147483647,
	"int_int32_over":               2147483648,
	"int_i64_min":                  int64(-1 << 63),
	"double_integral_huge":         1e10,
	"double_pi":                    3.141592653589793,
	"double_f32_exact":             0.5,
	"double_neg_zero":              0.0,
	"string_unicode":               "héllo ✓ 你好",
	"raw_300":                      repeatByte(7, 300),
	"list_mixed":                   []any{1, "a", nil, true, 2.5},
	"list_nested":                  []any{[]any{1, 2}, []any{3, []any{4, "x"}}},
	"list_empty":                   []any{},
	"map_simple":                   Map{{"a", 1}, {"b", []any{true}}},
	"map_int_keys":                 Map{{1, "x"}, {2, "y"}},
	"u8_200":                       uint8(200),
	"u16_70000_is_u32":             uint32(70000),
	"u64_big":                      uint64(1<<63 + 5),
	"i8_neg":                       int8(-3),
	"i16_200":                      int16(200),
	"f32_1p1":                      float32(1.1),
	"char16_z":                     Char16('z'),
	"decimal_1p50":                 MustDecimal("1.50"),
	"decimal_neg":                  MustDecimal("-0.0000000000000000000000000001"),
	"decimal_whole":                MustDecimal("42"),
	"datetime":                     time.Date(1999, 12, 31, 23, 59, 59, 123_000_000, time.UTC),
	"datetime_pre_1970":            time.Date(1901, 1, 1, 0, 0, 0, 0, time.UTC),
	"uuid":                         UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	"tru_i32":                      T.I32,
	"tru_nullable_list":            T.Nullable(T.List(T.String)),
	"tru_map_of_nullable":          T.Map(T.String, T.Nullable(T.I32)),
	"tru_tuple3":                   T.Tuple(T.U8, T.List(T.F64), T.Bool),
	"typed_list_i32":               []int32{1, -2, 300, 70000, -5},
	"typed_list_i16_zigzag":        []int16{0, -1, 63, -64, 64, 32767, -32768},
	"typed_list_i16_long_run":      rangeInts(100, func(i int) int16 { return int16(i*300 - 10000) }),
	"typed_list_u16_long_literals": rangeInts(300, func(i int) uint16 { return uint16(i % 100) }),
	"typed_list_u32":               []uint32{0, 255, 256, 65536, 4294967295},
	"typed_list_i64":               []int64{1, -(1 << 40), 1 << 62, -5},
	"typed_list_u64":               []uint64{1, 1 << 40, 1<<63 + 7, 5},
	"typed_list_u64_huge_run":      rangeInts(20, func(i int) uint64 { return two40 + uint64(i) }),
	"typed_list_empty":             []int32{},
	"typed_list_u8":                TypedList{T.U8, []int{1, 2, 200}},
	"typed_list_i8":                []int8{-1, 2, -128},
	"typed_list_char":              []Char16{97, 98, 0x4e2d},
	"typed_list_string":            []string{"a", "bb", ""},
	"typed_list_dynamic":           TypedList{T.Dynamic, []any{1, "x", nil, []any{2}}},
	"typed_list_f64":               []float64{1.5, 2, 3.25},
	"typed_list_of_typed_lists":    [][]int32{{1, 2}, {3}},
	"typed_map_string_i32":         map[string]int32{"a": 1, "b": 300},
	"typed_map_u8_dynamic":         map[uint8]any{1: "x", 2: []any{1, 2}},
	"typed_map_empty":              map[string]string{},
	"typed_tuple2":                 TypedTuple{[]Tru{T.I32, T.String}, []any{1, "a"}},
	"typed_tuple3_nested":          TypedTuple{[]Tru{T.List(T.I32), T.Bool, T.F64}, []any{[]int32{1}, true, 2.5}},
	"list_of_same_typed_lists":     []any{[]int32{1}, []int32{2, 3}, []int32{}},
	"list_of_mixed_typed_lists":    []any{[]int32{1}, []string{"a"}, []string{"b"}},
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestComposeMatchesEsiurTs(t *testing.T) {
	vs := loadVectors(t)
	if len(vs) != len(goVectors) {
		t.Errorf("fixture has %d vectors, the Go table %d", len(vs), len(goVectors))
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			value, ok := goVectors[v.Name]
			if !ok {
				t.Fatalf("no Go value for vector %s", v.Name)
			}
			got, err := Compose(value)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != v.Hex {
				t.Errorf("compose mismatch\n got %x\nwant %s", got, v.Hex)
			}
		})
	}
}

func TestTsBytesDecodeToAStableValue(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.Hex)
			decoded, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Parse(MustCompose(decoded))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(again, decoded) {
				t.Errorf("unstable: %#v then %#v", decoded, again)
			}
		})
	}
}

func TestTypedVectorsDecodeToTheirGoValue(t *testing.T) {
	want := map[string]any{
		"typed_list_i32":            []int32{1, -2, 300, 70000, -5},
		"typed_list_u64":            []uint64{1, 1 << 40, 1<<63 + 7, 5},
		"typed_list_u8":             []byte{1, 2, 200},
		"typed_list_char":           []Char16{97, 98, 0x4e2d},
		"typed_list_string":         []string{"a", "bb", ""},
		"typed_list_dynamic":        []any{int8(1), "x", nil, []any{int8(2)}},
		"typed_list_f64":            []float64{1.5, 2, 3.25},
		"typed_list_of_typed_lists": [][]int32{{1, 2}, {3}},
		"typed_map_string_i32":      map[string]int32{"a": 1, "b": 300},
		"typed_map_u8_dynamic":      map[uint8]any{1: "x", 2: []any{int8(1), int8(2)}},
		"typed_tuple2":              TypedTuple{[]Tru{T.I32, T.String}, []any{int32(1), "a"}},
		"tru_tuple3":                T.Tuple(T.U8, T.List(T.F64), T.Bool),
		"decimal_1p50":              MustDecimal("1.50"),
		"datetime":                  time.Date(1999, 12, 31, 23, 59, 59, 123_000_000, time.UTC),
		"map_int_keys":              Map{{int8(1), "x"}, {int8(2), "y"}},
	}
	for _, v := range loadVectors(t) {
		expected, ok := want[v.Name]
		if !ok {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.Hex)
			got, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, expected) {
				t.Errorf("got %#v\nwant %#v", got, expected)
			}
		})
	}
}

func TestInt128RoundTrip(t *testing.T) {
	for _, s := range []string{"0", "-1", "170141183460469231731687303715884105727", "-170141183460469231731687303715884105728"} {
		b, _ := new(big.Int).SetString(s, 10)
		v, err := Int128FromBig(b)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(MustCompose(v))
		if err != nil || got.(Int128).String() != s {
			t.Errorf("%s: got %v %v", s, got, err)
		}
	}
}
