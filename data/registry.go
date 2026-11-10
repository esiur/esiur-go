package data

import (
	"fmt"
	"reflect"
	"sync"
)

// TypeDefProperty is one property of a registered record, in wire order.
type TypeDefProperty struct {
	Name      string
	ValueType Tru
	field     []int
}

// TypeDefConstant is one constant of a registered enum.
type TypeDefConstant struct {
	Name  string
	Value any
	Index int
}

// TypeDefinition is a registered record or enum: what the codec needs to read and write it.
type TypeDefinition struct {
	ID         uint64
	Kind       TypeDefKind
	Name       string
	Properties []TypeDefProperty
	Constants  []TypeDefConstant
	// GoType is the Go type values decode to; nil decodes records to map[string]any and enums
	// to their constant's value.
	GoType reflect.Type
}

// ConstantIndex is the index of the enum constant equal to value.
func (d *TypeDefinition) ConstantIndex(value any) (int, bool) {
	for _, c := range d.Constants {
		if keysEqual(c.Value, value) {
			return c.Index, true
		}
	}
	return 0, false
}

// ConstantValue is the enum value at index, converted to GoType when set.
func (d *TypeDefinition) ConstantValue(index int) (any, error) {
	if index < 0 || index >= len(d.Constants) {
		return nil, parseErr("Enum '%s' has no constant at index %d.", d.Name, index)
	}
	raw := d.Constants[index].Value
	if d.GoType != nil {
		v, err := Convert(raw, d.GoType)
		if err != nil {
			return nil, err
		}
		return v.Interface(), nil
	}
	return raw, nil
}

// TypeRegistry is the record and enum definitions known to this process. Ids are handed out
// from 1 in registration order, like esiur-ts's Warehouse, unless one is requested.
type TypeRegistry struct {
	mu      sync.RWMutex
	byID    map[uint64]*TypeDefinition
	byType  map[reflect.Type]*TypeDefinition
	counter uint64
}

// NewTypeRegistry returns an empty registry.
func NewTypeRegistry() *TypeRegistry {
	return &TypeRegistry{byID: map[uint64]*TypeDefinition{}, byType: map[reflect.Type]*TypeDefinition{}}
}

func (r *TypeRegistry) allocate(requested uint64) (uint64, error) {
	if requested != 0 {
		if _, taken := r.byID[requested]; taken {
			return 0, fmt.Errorf("esiur: TypeDef id %d is already registered", requested)
		}
		return requested, nil
	}
	for {
		r.counter++
		if _, taken := r.byID[r.counter]; !taken {
			return r.counter, nil
		}
	}
}

// Add registers a prebuilt definition (for example one received from a peer). A zero ID is
// allocated.
func (r *TypeRegistry) Add(def *TypeDefinition) (*TypeDefinition, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.add(def)
}

func (r *TypeRegistry) add(def *TypeDefinition) (*TypeDefinition, error) {
	id, err := r.allocate(def.ID)
	if err != nil {
		return nil, err
	}
	if def.GoType != nil {
		if _, taken := r.byType[def.GoType]; taken {
			return nil, fmt.Errorf("esiur: %s is already registered", def.GoType)
		}
	}
	def.ID = id
	r.byID[id] = def
	if def.GoType != nil {
		r.byType[def.GoType] = def
	}
	return def, nil
}

// RegisterRecord registers the struct type of sample (a value or pointer) as a record. Its
// exported fields are the record's properties in declaration order; an `esiur:"name"` tag
// renames one and `esiur:"-"` skips it. An empty name uses the Go type name; id 0 allocates one.
func (r *TypeRegistry) RegisterRecord(sample any, name string, id uint64) (*TypeDefinition, error) {
	t := reflect.TypeOf(sample)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("esiur: a record must be a struct, got %v", t)
	}
	if name == "" {
		name = t.Name()
	}
	var props []TypeDefProperty
	seen := map[string]bool{}
	for _, f := range reflect.VisibleFields(t) {
		if !f.IsExported() || f.Anonymous || f.Tag.Get("esiur") == "-" {
			continue
		}
		wn := wireName(f)
		if seen[wn] {
			return nil, fmt.Errorf("esiur: record %s has two properties named %s", name, wn)
		}
		seen[wn] = true
		props = append(props, TypeDefProperty{Name: wn, field: f.Index})
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	def, err := r.add(&TypeDefinition{ID: id, Kind: KindRecord, Name: name, GoType: t})
	if err != nil {
		return nil, err
	}
	// Property types are resolved after registration so a record may refer to itself.
	for i := range props {
		f := t.FieldByIndex(props[i].field)
		props[i].ValueType = r.truOfLocked(f.Type)
	}
	def.Properties = props
	return def, nil
}

func (r *TypeRegistry) truOfLocked(t reflect.Type) Tru {
	if def, ok := r.byType[t]; ok {
		return TruTypeDef{TypeID: def.ID}
	}
	if t.Kind() == reflect.Pointer {
		if def, ok := r.byType[t.Elem()]; ok {
			return TruTypeDef{TypeID: def.ID, IsNullable: true}
		}
	}
	return TruOf(t, nil)
}

// EnumConstant names one value of an enum.
type EnumConstant struct {
	Name  string
	Value any
}

// RegisterEnum registers the (named integer) type of sample as an enum whose constants travel
// as their position in constants.
func (r *TypeRegistry) RegisterEnum(sample any, name string, id uint64, constants ...EnumConstant) (*TypeDefinition, error) {
	t := reflect.TypeOf(sample)
	if t == nil {
		return nil, fmt.Errorf("esiur: an enum needs a sample value")
	}
	if len(constants) > 256 {
		return nil, fmt.Errorf("esiur: an enum travels as a one-byte index, so it has at most 256 members")
	}
	if name == "" {
		name = t.Name()
	}
	defs := make([]TypeDefConstant, len(constants))
	for i, c := range constants {
		defs[i] = TypeDefConstant{Name: c.Name, Value: c.Value, Index: i}
	}
	return r.Add(&TypeDefinition{ID: id, Kind: KindEnum, Name: name, Constants: defs, GoType: t})
}

// ByID returns the definition registered under id.
func (r *TypeRegistry) ByID(id uint64) (*TypeDefinition, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.byID[id]
	return d, ok
}

// ByGoType returns the definition registered for t.
func (r *TypeRegistry) ByGoType(t reflect.Type) (*TypeDefinition, bool) {
	if r == nil || t == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.byType[t]
	return d, ok
}

// DefinitionOf is the definition of a registered record or enum value (exact type only).
func (r *TypeRegistry) DefinitionOf(value any) (*TypeDefinition, bool) {
	t := reflect.TypeOf(value)
	if t != nil && t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Struct {
		if d, ok := r.ByGoType(t.Elem()); ok && d.Kind == KindRecord {
			return d, true
		}
	}
	return r.ByGoType(t)
}

// NameOf is the name a TypeDef id stands for.
func (r *TypeRegistry) NameOf(id uint64) (string, error) {
	if d, ok := r.ByID(id); ok {
		return d.Name, nil
	}
	return "", fmt.Errorf("esiur: TypeDef %d is not registered", id)
}

// Len is the number of registered definitions.
func (r *TypeRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}
