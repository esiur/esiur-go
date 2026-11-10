package data

import (
	"encoding/binary"
	"math/bits"
)

// TduClass is the top two bits of a TDU identifier; it selects how the payload length is framed.
type TduClass uint8

const (
	TduFixed     TduClass = 0 // length implied by the identifier's exponent
	TduDynamic   TduClass = 1 // length-prefixed payload
	TduTyped     TduClass = 2 // length-prefixed, may carry type metadata
	TduExtension TduClass = 3
	TduInvalid   TduClass = 4 // not enough bytes / not a TDU
)

// TduIdentifier is the leading type byte: [class:2][size-or-exponent:3][index:3].
type TduIdentifier = uint8

const (
	// Fixed, zero payload
	IDNull        TduIdentifier = 0x00
	IDFalse       TduIdentifier = 0x01
	IDTrue        TduIdentifier = 0x02
	IDNotModified TduIdentifier = 0x03
	IDInfinity    TduIdentifier = 0x04
	// Fixed, 1 byte
	IDUInt8            TduIdentifier = 0x08
	IDInt8             TduIdentifier = 0x09
	IDChar8            TduIdentifier = 0x0A
	IDLocalResource8   TduIdentifier = 0x0B
	IDRemoteResource8  TduIdentifier = 0x0C
	IDLocalProcedure8  TduIdentifier = 0x0D
	IDRemoteProcedure8 TduIdentifier = 0x0E
	// Fixed, 2 bytes
	IDUInt16            TduIdentifier = 0x10
	IDInt16             TduIdentifier = 0x11
	IDChar16            TduIdentifier = 0x12
	IDLocalResource16   TduIdentifier = 0x13
	IDRemoteResource16  TduIdentifier = 0x14
	IDLocalProcedure16  TduIdentifier = 0x15
	IDRemoteProcedure16 TduIdentifier = 0x16
	// Fixed, 4 bytes
	IDUInt32            TduIdentifier = 0x18
	IDInt32             TduIdentifier = 0x19
	IDFloat32           TduIdentifier = 0x1A
	IDLocalResource32   TduIdentifier = 0x1B
	IDRemoteResource32  TduIdentifier = 0x1C
	IDLocalProcedure32  TduIdentifier = 0x1D
	IDRemoteProcedure32 TduIdentifier = 0x1E
	// Fixed, 8 bytes
	IDUInt64   TduIdentifier = 0x20
	IDInt64    TduIdentifier = 0x21
	IDFloat64  TduIdentifier = 0x22
	IDDateTime TduIdentifier = 0x23
	// Fixed, 16 bytes
	IDUInt128    TduIdentifier = 0x28
	IDInt128     TduIdentifier = 0x29
	IDDecimal128 TduIdentifier = 0x2A
	IDUUID       TduIdentifier = 0x2B
	// Dynamic
	IDRawData      TduIdentifier = 0x40
	IDString       TduIdentifier = 0x41
	IDList         TduIdentifier = 0x42
	IDResourceList TduIdentifier = 0x43
	IDRecordList   TduIdentifier = 0x44
	IDResourceLink TduIdentifier = 0x45
	IDMap          TduIdentifier = 0x46
	IDMapList      TduIdentifier = 0x47
	// Typed
	IDTyped   TduIdentifier = 0x80
	IDTypeDef TduIdentifier = 0x81
	IDTru     TduIdentifier = 0x82
	// Extension
	IDTypeContinuation TduIdentifier = 0xC0
	IDTypeOfTarget     TduIdentifier = 0xC1
)

// FramedHeader is the header of a length-prefixed TDU: the identifier with the length-of-length
// in bits 3-5, then the content length big-endian. Empty payloads omit both.
func FramedHeader(id byte, contentLength int) []byte {
	return appendFramedHeader(nil, id, contentLength)
}

func appendFramedHeader(b []byte, id byte, contentLength int) []byte {
	if contentLength == 0 {
		return append(b, id)
	}
	n := (bits.Len64(uint64(contentLength)) + 7) / 8
	if n > 7 {
		panic("esiur: TDU payload too large")
	}
	b = append(b, id|byte(n<<3))
	for i := n - 1; i >= 0; i-- {
		b = append(b, byte(uint64(contentLength)>>(8*i)))
	}
	return b
}

// ComposeTdu encodes a Fixed, Dynamic or Extension TDU (and TypeDef/TRU, which carry no metadata).
func ComposeTdu(identifier byte, payload []byte) []byte {
	if TduClass(identifier>>6) == TduFixed {
		out := make([]byte, 0, 1+len(payload))
		return append(append(out, identifier), payload...)
	}
	out := appendFramedHeader(make([]byte, 0, len(payload)+9), identifier, len(payload))
	return append(out, payload...)
}

// ParsedTdu is a measured TDU pointing back into its source buffer.
type ParsedTdu struct {
	Identifier    byte
	Index         byte
	Class         TduClass
	PayloadOffset int
	PayloadLength int
	Data          []byte
	Exponent      byte
	// TotalLength is the TDU's size; for an invalid TDU it is how many more bytes are needed.
	TotalLength int
	Ends        int
	// Metadata is the type metadata of a plain Typed TDU (0x80); nil for every other TDU.
	Metadata Tru
	// Offset of the TDU's identifier byte in Data.
	TduOffset int
}

// Valid reports whether a whole TDU was found.
func (t *ParsedTdu) Valid() bool { return t.Class != TduInvalid }

// Payload is the TDU's content (after its header and, for Typed, its metadata).
func (t *ParsedTdu) Payload() []byte {
	return t.Data[t.PayloadOffset : t.PayloadOffset+t.PayloadLength]
}

// Bytes is the whole TDU (identifier, length and payload), ready to hand to Parse.
func (t *ParsedTdu) Bytes() []byte {
	return t.Data[t.TduOffset : t.TduOffset+t.TotalLength]
}

func invalidTdu(needed int) ParsedTdu {
	return ParsedTdu{Class: TduInvalid, TotalLength: needed}
}

// ParseTdu measures the TDU at offset. A plain Typed TDU (0x80) has its leading Tru metadata
// parsed into Metadata, and its payload then starts after it; TypeDef (0x81) and TRU (0x82) are
// framed payloads without a metadata prefix. An invalid result (not enough data) is not an error;
// an oversized declaration or malformed metadata is.
func ParseTdu(data []byte, offset, ends int, limits Limits) (ParsedTdu, error) {
	return parseTdu(data, offset, ends, limits.MaximumPayloadLength, limits.MaximumTypeMetadataDepth, true)
}

// MeasureTdu delimits the TDU at offset without decoding anything (esiur-ts PlainTdu). A Typed
// TDU's metadata is not read, so Payload covers metadata and value.
func MeasureTdu(data []byte, offset, ends int, maximumPayloadLength int) (ParsedTdu, error) {
	return parseTdu(data, offset, ends, maximumPayloadLength, 0, false)
}

func parseTdu(data []byte, offset, ends, maxPayload, maxDepth int, parseMetadata bool) (ParsedTdu, error) {
	if offset >= ends {
		return invalidTdu(1), nil
	}
	start := offset
	header := data[offset]
	offset++
	class := TduClass(header >> 6)

	if class == TduFixed {
		exponent := (header & 0x38) >> 3
		tdu := ParsedTdu{
			Identifier: header, Index: header & 0x7, Class: class, Data: data,
			Exponent: exponent, Ends: ends, TduOffset: start, PayloadOffset: offset,
		}
		if exponent == 0 {
			tdu.TotalLength = 1
			return tdu, nil
		}
		length := 1 << (exponent - 1)
		if ends-offset < length {
			return invalidTdu(length - (ends - offset)), nil
		}
		tdu.PayloadLength = length
		tdu.TotalLength = 1 + length
		return tdu, nil
	}

	lengthSize := int((header >> 3) & 0x7)
	if ends-offset < lengthSize {
		return invalidTdu(lengthSize - (ends - offset)), nil
	}
	var length uint64
	for i := 0; i < lengthSize; i++ {
		length = length<<8 | uint64(data[offset+i])
	}
	offset += lengthSize
	// Reject an oversized declaration before it can justify waiting for more bytes.
	if err := EnsurePacketSize(length, maxPayload); err != nil {
		return ParsedTdu{}, err
	}
	if uint64(ends-offset) < length {
		return invalidTdu(int(length) - (ends - offset)), nil
	}
	n := int(length)

	if parseMetadata && class == TduTyped && header&0xC7 == 0x80 {
		tru, size, err := ParseTru(data, offset, offset+n, maxDepth)
		if err != nil {
			return ParsedTdu{}, err
		}
		return ParsedTdu{
			Identifier: IDTyped, Class: class, Data: data,
			PayloadOffset: offset + size, PayloadLength: n - size,
			TotalLength: 1 + lengthSize + n, Ends: ends, Metadata: tru, TduOffset: start,
		}, nil
	}

	return ParsedTdu{
		Identifier: header & 0xC7, Index: header & 0x7, Class: class, Data: data,
		PayloadOffset: offset, PayloadLength: n, TotalLength: 1 + lengthSize + n,
		Ends: ends, TduOffset: start,
	}, nil
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }
