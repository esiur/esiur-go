package data

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestOversizedDeclarationsAreRejectedBeforeWaiting(t *testing.T) {
	// A String TDU declaring 16 MB with a 3-byte length prefix: refused before any payload.
	raw := []byte{IDString | 3<<3, 0xFF, 0xFF, 0xFF}
	_, err := Parse(raw)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("want a limit error, got %v", err)
	}
	if _, err := ParseTdu(raw, 0, len(raw), DefaultLimits()); !errors.Is(err, ErrLimit) {
		t.Fatalf("ParseTdu: want a limit error, got %v", err)
	}
}

func TestCollectionAndDepthLimits(t *testing.T) {
	items := make([]any, 10)
	for i := range items {
		items[i] = i
	}
	p := NewParser(nil)
	p.Limits.MaximumCollectionItems = 5
	if _, err := p.Parse(MustCompose(items)); !errors.Is(err, ErrLimit) {
		t.Errorf("collection: %v", err)
	}
	if _, err := p.Parse(MustCompose(make([]int32, 6))); !errors.Is(err, ErrLimit) {
		t.Errorf("typed collection: %v", err)
	}

	var deep any = 1
	for i := 0; i < DefaultMaximumValueDepth+2; i++ {
		deep = []any{deep}
	}
	if _, err := Compose(deep); !errors.Is(err, ErrLimit) {
		t.Errorf("compose depth: %v", err)
	}

	tru := Tru(T.I32)
	for i := 0; i < 70; i++ {
		tru = T.List(tru)
	}
	if _, err := Parse(MustCompose(tru)); !errors.Is(err, ErrLimit) {
		t.Errorf("metadata depth: %v", err)
	}
}

func TestTruncatedInputIsAnError(t *testing.T) {
	full := MustCompose([]any{"abc", 1, []int32{1, 2, 3}})
	for n := 0; n < len(full); n++ {
		if _, err := Parse(full[:n]); !errors.Is(err, ErrParse) {
			t.Fatalf("prefix %d: want a parse error, got %v", n, err)
		}
	}
}

type sample struct {
	Indexed
	Name  string            `idx:"0"`
	Count *int32            `idx:"1"`
	Tags  []string          `idx:"2"`
	Extra map[string]string `idx:"3,typed"`
	Later any               `idx:"9"`
}

func TestIndexedStructuresRoundTripAndTolerateUnknownMembers(t *testing.T) {
	in := sample{Name: "x", Count: Ptr[int32](7), Tags: []string{"a"}, Extra: map[string]string{"k": "v"}}
	decoded, err := Parse(MustCompose(in))
	if err != nil {
		t.Fatal(err)
	}
	var out sample
	if err := FromIndexedMap(decoded, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("got %+v want %+v", out, in)
	}
	// An index the receiver does not know is ignored; a wrong type is refused.
	extended := TypedMap{T.U8, T.Dynamic, Map{{uint8(0), "y"}, {uint8(42), "future"}}}
	if err := FromIndexedMap(extended, &out); err != nil || out.Name != "y" {
		t.Errorf("unknown index: %+v %v", out, err)
	}
	wrong := TypedMap{T.U8, T.Dynamic, Map{{uint8(0), 5}}}
	if err := FromIndexedMap(wrong, &out); !errors.Is(err, ErrParse) {
		t.Errorf("wrong type: %v", err)
	}
}

func TestGoValuesRoundTrip(t *testing.T) {
	when := time.Date(2026, 11, 10, 12, 30, 45, 123456700, time.UTC)
	for _, v := range []any{
		int8(-5), uint64(1 << 60), float32(2.5), "text", []byte{1, 2}, when, MustDecimal("-12.345"),
		[]string{"a", "b"}, map[string]float64{"pi": 3.25}, [][]uint16{{1}, {2, 3}}, Char16('é'),
		UUID{0xFF, 1}, NotModified, ResourceLink("ep://host/sys/x"), ResourceID{Local: true, ID: 70000},
	} {
		got, err := Parse(MustCompose(v))
		if err != nil {
			t.Fatalf("%T: %v", v, err)
		}
		if !reflect.DeepEqual(got, v) {
			t.Errorf("%T: got %#v want %#v", v, got, v)
		}
	}
}

func TestConvert(t *testing.T) {
	got, err := As[[]float64]([]any{int8(1), float32(2.5), uint16(3)})
	if err != nil || !reflect.DeepEqual(got, []float64{1, 2.5, 3}) {
		t.Errorf("slice: %v %v", got, err)
	}
	if _, err := As[uint8](300); err == nil {
		t.Error("an overflowing conversion must fail")
	}
	m, err := As[map[string]int](Map{{"a", int8(1)}})
	if err != nil || m["a"] != 1 {
		t.Errorf("map: %v %v", m, err)
	}
}
