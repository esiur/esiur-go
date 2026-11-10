package data

// TypeDefKind says what a type definition describes.
type TypeDefKind uint8

const (
	KindResource TypeDefKind = 0
	KindRecord   TypeDefKind = 1
	KindEnum     TypeDefKind = 2
	KindFunction TypeDefKind = 3
)

// OrderingControl values.
const (
	OrderingStrict     = 0
	OrderingRelaxed    = 1
	OrderingLatestOnly = 2
)

// StreamMode values.
const (
	StreamNone = 0
	StreamPush = 1
	StreamPull = 2
)

// OperationEffects bits.
const (
	EffectsNone            = 0x00
	EffectsModifiesState   = 0x01
	EffectsCreatesResource = 0x02
	EffectsDeletesResource = 0x04
	EffectsExternal        = 0x08
	EffectsEmitsEvents     = 0x10
	EffectsUnknown         = 0x80
)

// PropertyDefFlags bits.
const (
	PropertyInherited  = 0x01
	PropertyDeprecated = 0x02
	PropertyReadOnly   = 0x04
	PropertyConstant   = 0x08
	PropertyVolatile   = 0x10
	PropertyHistorical = 0x20
)

// FunctionDefFlags bits.
const (
	FunctionInherited   = 0x01
	FunctionDeprecated  = 0x02
	FunctionStatic      = 0x04
	FunctionReadOnly    = 0x08
	FunctionIdempotent  = 0x10
	FunctionCancellable = 0x20
	FunctionPausable    = 0x40
)

// EventDefFlags bits.
const (
	EventInherited     = 0x01
	EventDeprecated    = 0x02
	EventAutoDelivered = 0x04
	EventHistorical    = 0x08
)

// ConstantDefFlags bits.
const (
	ConstantInherited  = 0x01
	ConstantDeprecated = 0x02
)

// ArgumentDefFlags bits.
const (
	ArgumentOptional = 0x01
	ArgumentVariadic = 0x02
)

// MemberDefInfo is what every member kind (property, function, event, constant, argument) shares.
type MemberDefInfo struct {
	Indexed
	Index int    `idx:"0x00"`
	Name  string `idx:"0x01"`
	// Flags is the raw flags byte; interpret it with the member kind's flag constants.
	Flags int `idx:"0x02"`

	Description        *string           `idx:"0x20"`
	Usage              *string           `idx:"0x21"`
	Examples           []any             `idx:"0x22"`
	Tags               []string          `idx:"0x23"`
	Unit               *string           `idx:"0x24"`
	Minimum            any               `idx:"0x25"`
	Maximum            any               `idx:"0x26"`
	AllowedValues      []any             `idx:"0x27"`
	Pattern            *string           `idx:"0x28"`
	Format             *string           `idx:"0x29"`
	Preconditions      []string          `idx:"0x2A"`
	Postconditions     []string          `idx:"0x2B"`
	Effects            int               `idx:"0x2C"`
	Warnings           []string          `idx:"0x2D"`
	RelatedMembers     []int             `idx:"0x2E"`
	DeprecationMessage *string           `idx:"0x2F"`
	Annotations        map[string]string `idx:"0x30"`
}

// PropertyDefInfo describes a property.
type PropertyDefInfo struct {
	MemberDefInfo
	ValueType       Tru `idx:"0x03"`
	OrderingControl int `idx:"0x04"`
	HistoryControl  int `idx:"0x05"`
	DefaultValue    any `idx:"0x06"`
}

// ArgumentDefInfo describes a function argument; its name is the inherited Name.
type ArgumentDefInfo struct {
	MemberDefInfo
	ValueType    Tru `idx:"0x03"`
	DefaultValue any `idx:"0x04"`
}

// FunctionDefInfo describes a function.
type FunctionDefInfo struct {
	MemberDefInfo
	Arguments  []ArgumentDefInfo `idx:"0x03"`
	ReturnType Tru               `idx:"0x04"`
	StreamMode int               `idx:"0x05"`
}

// EventDefInfo describes an event.
type EventDefInfo struct {
	MemberDefInfo
	ArgumentType    Tru     `idx:"0x03"`
	ArgumentName    *string `idx:"0x04"`
	OrderingControl int     `idx:"0x05"`
	HistoryControl  int     `idx:"0x06"`
}

// ConstantDefInfo describes a constant.
type ConstantDefInfo struct {
	MemberDefInfo
	ValueType Tru `idx:"0x03"`
	Value     any `idx:"0x04"`
}

// TypeDefInfo is a type definition as it travels in a TypeDef TDU (0x81).
type TypeDefInfo struct {
	Indexed
	Version    int32             `idx:"0x00"`
	ID         uint64            `idx:"0x01"`
	Name       string            `idx:"0x02"`
	Namespace  *string           `idx:"0x03"`
	Kind       TypeDefKind       `idx:"0x04"`
	Parent     *uint64           `idx:"0x05"`
	Properties []PropertyDefInfo `idx:"0x06"`
	Functions  []FunctionDefInfo `idx:"0x07"`
	Events     []EventDefInfo    `idx:"0x08"`
	Constants  []ConstantDefInfo `idx:"0x09"`
	// Signature is the id-independent hash of the definition, used to validate cached copies.
	Signature *uint64 `idx:"0x0A"`

	Usage       *string           `idx:"0x20"`
	Description *string           `idx:"0x21"`
	Example     any               `idx:"0x22"`
	Category    *string           `idx:"0x23"`
	Since       *string           `idx:"0x24"`
	Annotations map[string]string `idx:"0x25,typed"`
}

// TypeDefInfoFromMap builds a TypeDefInfo (and its nested member infos) from a decoded payload.
func TypeDefInfoFromMap(value any) (*TypeDefInfo, error) {
	info := &TypeDefInfo{}
	if err := FromIndexedMap(value, info); err != nil {
		return nil, err
	}
	return info, nil
}

// Ptr returns a pointer to v (handy for optional members).
func Ptr[V any](v V) *V { return &v }
