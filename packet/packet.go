package packet

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/esiur/esiur-go/data"
)

const hasTdu = 0x20

func bounds(b []byte, offset, ends int) error {
	if offset < 0 || offset > ends || ends > len(b) {
		return fmt.Errorf("esiur: invalid window [%d, %d) for a buffer of %d bytes", offset, ends, len(b))
	}
	return nil
}

// checkedTdu verifies the optional value of a packet being composed is exactly one complete
// TDU: anything else would shift every later packet on the stream out of frame.
func checkedTdu(tdu []byte) error {
	if tdu == nil {
		return nil
	}
	// The size budget is the receiver's business; only the framing is checked here.
	m, err := data.MeasureTdu(tdu, 0, len(tdu), 0)
	if err != nil || !m.Valid() || m.TotalLength != len(tdu) {
		return errors.New("esiur: a packet's value must be exactly one complete TDU")
	}
	return nil
}

// Packet is the EP session packet. Layout: a header byte [method:2][has-value:1][action:5], a
// four-byte little-endian callback id for requests and replies, then an optional value as one
// self-describing TDU. The value is only delimited here; decoding it may need the connection
// (remote resources, TypeDefs), so it is left to the caller.
type Packet struct {
	Method Method
	// Action is the low five bits of the header: a request, reply or notification action
	// depending on Method.
	Action     uint8
	CallbackID uint32
	// Tdu is the value, measured but not decoded; it points into the buffer passed to Parse.
	Tdu *data.ParsedTdu
}

// HasTdu reports whether the packet carries a value.
func (p *Packet) HasTdu() bool { return p.Tdu != nil }

// Parse reads a packet from b[offset:ends]. It returns the bytes consumed, or -n when the buffer
// is short and n more bytes are needed (the packet is then left untouched). It fails for a value
// that declares more than maximumPayloadLength bytes.
func (p *Packet) Parse(b []byte, offset, ends, maximumPayloadLength int) (int, error) {
	if err := bounds(b, offset, ends); err != nil {
		return 0, err
	}
	start := offset
	if offset >= ends {
		return -1, nil
	}
	header := b[offset]
	offset++
	method := Method(header >> 6)
	action := header & 0x1F
	var callbackID uint32
	if method == MethodRequest || method == MethodReply {
		if ends-offset < 4 {
			return -(4 - (ends - offset)), nil
		}
		callbackID = binary.LittleEndian.Uint32(b[offset:])
		offset += 4
	}
	var tdu *data.ParsedTdu
	if header&hasTdu != 0 {
		if offset >= ends {
			return -1, nil
		}
		m, err := data.MeasureTdu(b, offset, ends, maximumPayloadLength)
		if err != nil {
			return 0, err
		}
		if !m.Valid() {
			return -m.TotalLength, nil
		}
		offset += m.TotalLength
		tdu = &m
	}
	*p = Packet{Method: method, Action: action, CallbackID: callbackID, Tdu: tdu}
	return offset - start, nil
}

func compose(method Method, action uint8, callbackID *uint32, tdu []byte) ([]byte, error) {
	if action > 0x1F {
		return nil, errors.New("esiur: a packet action must fit in five bits")
	}
	if err := checkedTdu(tdu); err != nil {
		return nil, err
	}
	header := byte(method)<<6 | action
	if tdu != nil {
		header |= hasTdu
	}
	out := make([]byte, 0, 5+len(tdu))
	out = append(out, header)
	if callbackID != nil {
		out = binary.LittleEndian.AppendUint32(out, *callbackID)
	}
	return append(out, tdu...), nil
}

// ComposeRequest builds a request packet; tdu (nil for none) is the argument, already composed
// as one TDU.
func ComposeRequest(action uint8, callbackID uint32, tdu []byte) ([]byte, error) {
	return compose(MethodRequest, action, &callbackID, tdu)
}

// ComposeReply builds a reply packet; tdu (nil for none) is the result.
func ComposeReply(action uint8, callbackID uint32, tdu []byte) ([]byte, error) {
	return compose(MethodReply, action, &callbackID, tdu)
}

// ComposeNotification builds a notification packet (no callback id).
func ComposeNotification(action uint8, tdu []byte) ([]byte, error) {
	return compose(MethodNotification, action, nil, tdu)
}

// AuthPacket is the authentication-phase packet. Header byte [command:2][has-value:1][...]. For
// Initialize the low bits carry authMode<<2 | encryptionMode; for every other command they carry
// the AuthMethod (whose own top bits repeat the command). An optional TDU follows, typically a
// TypedMap<UInt8, Dynamic> keyed by AuthHeader.
type AuthPacket struct {
	Command AuthCommand
	// Method of a non-Initialize packet; MethodInitialize for an initialize packet.
	Method AuthMethod
	// AuthMode and EncryptionMode are only meaningful for Initialize; they may hold values this
	// version does not know (for the caller to refuse).
	AuthMode       AuthenticationMode
	EncryptionMode EncryptionMode
	Tdu            *data.ParsedTdu
}

// HasTdu reports whether the packet carries a value.
func (p *AuthPacket) HasTdu() bool { return p.Tdu != nil }

// Parse reads a packet from b[offset:ends]; it returns the bytes consumed, or -n when n more
// bytes are needed (the packet is then left untouched).
func (p *AuthPacket) Parse(b []byte, offset, ends, maximumPayloadLength int) (int, error) {
	if err := bounds(b, offset, ends); err != nil {
		return 0, err
	}
	start := offset
	if offset >= ends {
		return -1, nil
	}
	header := b[offset]
	offset++
	out := AuthPacket{Command: AuthCommand(header >> 6)}
	if out.Command == AuthInitialize {
		out.AuthMode = AuthenticationMode((header >> 2) & 0x3)
		out.EncryptionMode = EncryptionMode(header & 0x3)
	} else {
		out.Method = AuthMethod(header & 0xDF)
	}
	if header&hasTdu != 0 {
		if offset >= ends {
			return -1, nil
		}
		m, err := data.MeasureTdu(b, offset, ends, maximumPayloadLength)
		if err != nil {
			return 0, err
		}
		if !m.Valid() {
			return -m.TotalLength, nil
		}
		offset += m.TotalLength
		out.Tdu = &m
	}
	*p = out
	return offset - start, nil
}

// ComposeInitialize builds an Initialize packet; the two modes share the low four bits.
func ComposeInitialize(authMode AuthenticationMode, encryptionMode EncryptionMode, headersTdu []byte) ([]byte, error) {
	if authMode > 3 || encryptionMode > 3 {
		return nil, errors.New("esiur: the authentication and encryption modes must each fit in two bits")
	}
	if err := checkedTdu(headersTdu); err != nil {
		return nil, err
	}
	header := byte(AuthInitialize)<<6 | byte(authMode)<<2 | byte(encryptionMode)
	if headersTdu != nil {
		header |= hasTdu
	}
	return append([]byte{header}, headersTdu...), nil
}

// ComposeMethod builds a packet for any method; its top two bits already carry the command.
func ComposeMethod(method AuthMethod, headersTdu []byte) ([]byte, error) {
	if method&hasTdu != 0 {
		return nil, errors.New("esiur: an authentication method must be a byte without the 0x20 bit")
	}
	if err := checkedTdu(headersTdu); err != nil {
		return nil, err
	}
	header := byte(method)
	if headersTdu != nil {
		header |= hasTdu
	}
	return append([]byte{header}, headersTdu...), nil
}
