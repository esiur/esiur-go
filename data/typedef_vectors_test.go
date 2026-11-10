package data

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"
)

// Differential test of the TypeDef layer against the real esiur-ts encoder (fixture shared with
// esiur-python, tools/gen-typedef-vectors.mjs there).

type typedefFixture struct {
	Vectors []struct {
		Name  string   `json:"name"`
		Types []string `json:"types"`
		Hex   string   `json:"hex"`
	} `json:"vectors"`
	Signatures []struct {
		Name      string `json:"name"`
		Signature string `json:"signature"`
	} `json:"signatures"`
	Names []struct {
		Name   string `json:"name"`
		Name64 string `json:"name64"`
	} `json:"names"`
}

type Point struct {
	X int32 `esiur:"x"`
	Y int32 `esiur:"y"`
}

type PathRecord struct {
	Name   string `esiur:"name"`
	Points any    `esiur:"points"`
}

type Mixed struct {
	Label *string `esiur:"label"`
	Extra any     `esiur:"extra"`
	Ratio float64 `esiur:"ratio"`
}

type Color uint8

func registerFixtureTypes(t *testing.T, names []string) *TypeRegistry {
	r := NewTypeRegistry()
	for _, name := range names {
		var err error
		switch name {
		case "Point":
			_, err = r.RegisterRecord(Point{}, "", 0)
		case "Path":
			var def *TypeDefinition
			def, err = r.RegisterRecord(PathRecord{}, "PathRecord", 0)
			if err == nil {
				def.Properties[1].ValueType = T.List(T.I32)
			}
		case "Mixed":
			_, err = r.RegisterRecord(Mixed{}, "", 0)
		case "Color":
			_, err = r.RegisterEnum(Color(0), "Color", 0,
				EnumConstant{"RED", Color(0)}, EnumConstant{"GREEN", Color(1)}, EnumConstant{"BLUE", Color(2)})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func p(i uint64) *uint64 { return &i }

func holder(parent *uint64) *TypeDefInfo {
	return &TypeDefInfo{ID: 9, Name: "Holder", Kind: KindResource, Parent: parent, Properties: []PropertyDefInfo{
		{MemberDefInfo: MemberDefInfo{Index: 0, Name: "a"}, ValueType: TruTypeDef{TypeID: 3}},
		{MemberDefInfo: MemberDefInfo{Index: 1, Name: "b"}, ValueType: T.Nullable(TruTypeDef{TypeID: 300})},
		{MemberDefInfo: MemberDefInfo{Index: 2, Name: "c"}, ValueType: T.List(TruTypeDef{TypeID: 70000})},
	}}
}

var typedefVectors = map[string]any{
	"typedef_minimal": &TypeDefInfo{ID: 1, Name: "Point", Kind: KindRecord},
	"typedef_full_resource": &TypeDefInfo{
		Version: 3, ID: 7, Name: "Sensor", Namespace: Ptr("Acme.Devices"), Kind: KindResource,
		Parent: p(2), Signature: p(0x1122334455667788), Usage: Ptr("u"), Description: Ptr("A sensor"),
		Example: []any{1, "x"}, Category: Ptr("iot"), Since: Ptr("3.2"),
		Annotations: map[string]string{"owner": "ops", "tier": "gold"},
		Properties: []PropertyDefInfo{
			{MemberDefInfo: MemberDefInfo{Index: 0, Name: "temperature", Flags: 0x04, Description: Ptr("deg C"),
				Unit: Ptr("C"), Minimum: -40, Maximum: 125, Tags: []string{"a", "b"}, RelatedMembers: []int{1, 2},
				Annotations: map[string]string{"k": "v"}},
				ValueType: T.F64, OrderingControl: 2, HistoryControl: 1, DefaultValue: 20.5},
			{MemberDefInfo: MemberDefInfo{Index: 1, Name: "label"}, ValueType: T.Nullable(T.String)},
			{MemberDefInfo: MemberDefInfo{Index: 2, Name: "readings", Flags: 0x22}, ValueType: T.List(T.Map(T.String, T.I32))},
		},
		Functions: []FunctionDefInfo{
			{MemberDefInfo: MemberDefInfo{Index: 0, Name: "calibrate", Flags: 0x14, Effects: 0x11,
				Preconditions: []string{"idle"}, Warnings: []string{"slow"}, DeprecationMessage: Ptr("use x")},
				ReturnType: T.Bool, StreamMode: 1, Arguments: []ArgumentDefInfo{
					{MemberDefInfo: MemberDefInfo{Index: 0, Name: "offset"}, ValueType: T.F64},
					{MemberDefInfo: MemberDefInfo{Index: 1, Name: "mode", Flags: 3}, ValueType: T.String, DefaultValue: "auto"},
				}},
			{MemberDefInfo: MemberDefInfo{Index: 1, Name: "reset"}},
		},
		Events: []EventDefInfo{{MemberDefInfo: MemberDefInfo{Index: 0, Name: "changed", Flags: 0x04},
			ArgumentType: T.F64, ArgumentName: Ptr("value"), OrderingControl: 1, HistoryControl: 2}},
		Constants: []ConstantDefInfo{
			{MemberDefInfo: MemberDefInfo{Index: 0, Name: "MaxRate"}, ValueType: T.U16, Value: 1000},
			{MemberDefInfo: MemberDefInfo{Index: 1, Name: "Unit", Flags: 2}, ValueType: T.String, Value: "C"},
		},
	},
	"typedef_with_type_references": holder(nil),
	"typedef_enum": &TypeDefInfo{ID: 2, Name: "Color", Kind: KindEnum, Constants: []ConstantDefInfo{
		{MemberDefInfo: MemberDefInfo{Index: 0, Name: "Red"}, Value: 0},
		{MemberDefInfo: MemberDefInfo{Index: 1, Name: "Green"}, Value: 1},
		{MemberDefInfo: MemberDefInfo{Index: 2, Name: "Blue"}, Value: 2},
	}},
	"list_of_typedefs":                  []any{&TypeDefInfo{ID: 1, Name: "A", Kind: KindRecord}, &TypeDefInfo{ID: 2, Name: "B", Kind: KindRecord}},
	"record_point":                      Point{3, 4},
	"record_point_big_id_values":        Point{70000, -5},
	"record_path_dynamic_list":          PathRecord{"seg", []any{1, 2, 3}},
	"record_path_typed_list":            PathRecord{"seg", []int32{1, 2, 3}},
	"record_mixed_nulls":                Mixed{nil, nil, 0.5},
	"record_mixed_filled":               Mixed{Ptr("hi"), Map{{"a", []any{1, 2}}}, 2.25},
	"record_in_list_continuation":       []any{Point{1, 2}, Point{3, 4}, Point{5, 6}},
	"record_nested_in_dynamic_property": Mixed{Ptr("n"), Point{7, 8}, 1.5},
	"enum_green":                        Color(1),
	"enum_in_list":                      []any{Color(0), Color(2), Color(2)},
	"enum_and_record_ids":               []any{Point{1, 1}, Color(0)},
	"enum_then_record_ids":              []any{Color(0), Point{1, 1}},
	"map_of_records":                    Map{{"p", Point{2, 3}}},
}

var signatureVectors = map[string]*TypeDefInfo{
	"signature_with_references": holder(p(2)),
	"signature_plain": {ID: 5, Name: "Plain", Kind: KindRecord, Properties: []PropertyDefInfo{
		{MemberDefInfo: MemberDefInfo{Index: 0, Name: "x"}, ValueType: T.I32}}},
	"signature_unknown_parent": {ID: 5, Name: "Orphan", Kind: KindResource, Parent: p(99)},
}

func loadTypedefFixture(t *testing.T) typedefFixture {
	raw, err := os.ReadFile("testdata/ts-typedef-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f typedefFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTypeDefComposeMatchesEsiurTs(t *testing.T) {
	f := loadTypedefFixture(t)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			value, ok := typedefVectors[v.Name]
			if !ok {
				t.Fatalf("no Go value for %s", v.Name)
			}
			types := registerFixtureTypes(t, v.Types)
			got, err := (&Composer{Types: types}).Compose(value)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != v.Hex {
				t.Errorf("compose mismatch\n got %x\nwant %s", got, v.Hex)
			}
			// esiur-ts bytes decode to a value that composes back to the same bytes.
			raw, _ := hex.DecodeString(v.Hex)
			decoded, err := NewParser(types).Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			again, err := (&Composer{Types: types}).Compose(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(again) != v.Hex {
				t.Errorf("decoded %#v recomposes as\n%x", decoded, again)
			}
		})
	}
}

func TestTypeDefDecodesToGoValues(t *testing.T) {
	types := registerFixtureTypes(t, []string{"Point", "Color"})
	check := func(value, want any) {
		t.Helper()
		got, err := NewParser(types).Parse(must((&Composer{Types: types}).Compose(value)))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	check(Point{70000, -5}, Point{70000, -5})
	check(Color(2), Color(2))
	check([]any{Point{1, 2}, Color(1)}, []any{Point{1, 2}, Color(1)})

	info := typedefVectors["typedef_full_resource"].(*TypeDefInfo)
	decoded, err := Parse(MustCompose(info))
	if err != nil {
		t.Fatal(err)
	}
	d := decoded.(*TypeDefInfo)
	if d.Name != "Sensor" || *d.Namespace != "Acme.Devices" || len(d.Functions[0].Arguments) != 2 ||
		d.Functions[0].Arguments[1].DefaultValue != "auto" || !d.Properties[2].ValueType.Match(T.List(T.Map(T.String, T.I32))) ||
		d.Annotations["tier"] != "gold" || d.Properties[0].Annotations["k"] != "v" || *d.Signature != 0x1122334455667788 {
		t.Errorf("decoded TypeDefInfo differs: %+v", d)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestSignatureMatchesEsiurTs(t *testing.T) {
	names := map[uint64]string{3: "Alpha", 300: "Beta", 70000: "Gamma", 2: "Base"}
	nameOf := func(id uint64) (string, error) {
		if n, ok := names[id]; ok {
			return n, nil
		}
		return "", fmt.Errorf("unknown %d", id)
	}
	for _, v := range loadTypedefFixture(t).Signatures {
		got, err := TypeDefSignature(signatureVectors[v.Name], nameOf)
		if err != nil {
			t.Fatal(err)
		}
		if strconv.FormatUint(got, 10) != v.Signature {
			t.Errorf("%s: got %d want %s", v.Name, got, v.Signature)
		}
	}
	for _, n := range loadTypedefFixture(t).Names {
		if strconv.FormatUint(Name64(n.Name), 10) != n.Name64 {
			t.Errorf("name64(%q) = %d want %s", n.Name, Name64(n.Name), n.Name64)
		}
	}
}
