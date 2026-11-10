package data

import (
	"fmt"
	"math/bits"
)

// GroupCodec is the group-varint codec for one integer width and signedness (port of esiur-ts
// gvwie / C# Gvwie.GroupIntNNCodec).
//
// One header byte frames a run: 1 | count-field[countBits] | (width-1)[widthBits] where
// countBits + widthBits == 7. A value that fits in 7 bits (after zig-zag for signed widths) is a
// single literal byte instead. Count-field values above maxShortField announce an extended count
// stored in 1-4 little-endian bytes after the header.
type GroupCodec struct {
	CountBits int
	Bits      int
	Signed    bool
}

var (
	GroupInt16  = GroupCodec{CountBits: 6, Bits: 16, Signed: true}
	GroupInt32  = GroupCodec{CountBits: 5, Bits: 32, Signed: true}
	GroupInt64  = GroupCodec{CountBits: 4, Bits: 64, Signed: true}
	GroupUInt16 = GroupCodec{CountBits: 6, Bits: 16}
	GroupUInt32 = GroupCodec{CountBits: 5, Bits: 32}
	GroupUInt64 = GroupCodec{CountBits: 4, Bits: 64}
)

func (c GroupCodec) maxWidth() int      { return c.Bits / 8 }
func (c GroupCodec) widthBits() int     { return 7 - c.CountBits }
func (c GroupCodec) countFieldMax() int { return (1 << c.CountBits) - 1 }
func (c GroupCodec) maxShortField() int { return c.countFieldMax() - 4 }
func (c GroupCodec) shortMaxCount() int { return c.maxShortField() + 1 }
func (c GroupCodec) mask() uint64       { return ^uint64(0) >> (64 - c.Bits) }
func (c GroupCodec) widthOf(z uint64) int {
	w := (bits.Len64(z) + 7) / 8
	if w < 1 {
		w = 1
	}
	return min(w, c.maxWidth())
}

// ToZ maps a value (int64 bits for signed codecs, uint64 for unsigned) to its zig-zag form.
func (c GroupCodec) toZ(v uint64) uint64 {
	if c.Signed {
		s := int64(v)
		return (uint64(s<<1) ^ uint64(s>>63)) & c.mask()
	}
	return v & c.mask()
}

func (c GroupCodec) fromZ(z uint64) uint64 {
	if c.Signed {
		return uint64(int64(z>>1) ^ -int64(z&1))
	}
	return z
}

// EncodeSigned encodes signed values; each must fit the codec width.
func (c GroupCodec) EncodeSigned(values []int64) ([]byte, error) {
	raw := make([]uint64, len(values))
	lo, hi := -(int64(1) << (c.Bits - 1)), int64(1)<<(c.Bits-1)-1
	if c.Bits == 64 {
		lo, hi = -1<<63, 1<<63-1
	}
	for i, v := range values {
		if !c.Signed && v < 0 || c.Signed && (v < lo || v > hi) || !c.Signed && c.Bits < 64 && uint64(v) > c.mask() {
			return nil, fmt.Errorf("esiur: value %d does not fit in %d-bit group codec", v, c.Bits)
		}
		raw[i] = uint64(v)
	}
	return c.encode(raw), nil
}

// EncodeUnsigned encodes unsigned values; each must fit the codec width.
func (c GroupCodec) EncodeUnsigned(values []uint64) ([]byte, error) {
	for _, v := range values {
		if c.Signed && v > uint64(1)<<(c.Bits-1)-1 || v > c.mask() {
			return nil, fmt.Errorf("esiur: value %d does not fit in %d-bit group codec", v, c.Bits)
		}
	}
	return c.encode(values), nil
}

func (c GroupCodec) encode(items []uint64) []byte {
	out := make([]byte, 0, len(items)*2)
	widthMask := (1 << c.widthBits()) - 1
	for i := 0; i < len(items); {
		z := c.toZ(items[i])
		if z <= 0x7F {
			out = append(out, byte(z))
			i++
			continue
		}
		start, width, count := i, c.widthOf(z), 1
		for i+count < len(items) {
			z2 := c.toZ(items[i+count])
			if z2 <= 0x7F || c.widthOf(z2) != width {
				break
			}
			count++
		}
		if count <= c.shortMaxCount() {
			out = append(out, byte(0x80|((count-1)<<c.widthBits())|((width-1)&widthMask)))
		} else {
			extra := count - (c.shortMaxCount() + 1)
			lol := 4
			switch {
			case extra <= 0xFF:
				lol = 1
			case extra <= 0xFFFF:
				lol = 2
			case extra <= 0xFFFFFF:
				lol = 3
			}
			groupBits := c.maxShortField() + lol
			out = append(out, byte(0x80|(groupBits<<c.widthBits())|((width-1)&widthMask)))
			for k := 0; k < lol; k++ {
				out = append(out, byte(extra>>(8*k)))
			}
		}
		for k := 0; k < count; k++ {
			z := c.toZ(items[start+k])
			for b := 0; b < width; b++ {
				out = append(out, byte(z>>(8*b)))
			}
		}
		i += count
	}
	return out
}

// Decode decodes data. validate sees the running total before any run is read, so a hostile
// count is rejected without being materialised. Values are returned as raw 64-bit patterns:
// reinterpret them as int64 for signed codecs.
func (c GroupCodec) Decode(data []byte, validate func(count int) error) ([]uint64, error) {
	var result []uint64
	pos, limit := 0, len(data)
	widthMask := (1 << c.widthBits()) - 1
	take := func(width int) (uint64, error) {
		if pos+width > limit {
			return 0, parseErr("Buffer underflow while reading a group payload.")
		}
		var v uint64
		for b := 0; b < width; b++ {
			v |= uint64(data[pos+b]) << (8 * b)
		}
		pos += width
		return v, nil
	}
	for pos < limit {
		header := data[pos]
		pos++
		if header&0x80 == 0 {
			if validate != nil {
				if err := validate(len(result) + 1); err != nil {
					return nil, err
				}
			}
			result = append(result, c.fromZ(uint64(header&0x7F)))
			continue
		}
		countField := (int(header) >> c.widthBits()) & c.countFieldMax()
		width := (int(header) & widthMask) + 1
		var count int
		if countField <= c.maxShortField() {
			count = countField + 1
		} else {
			extra, err := take(countField - c.maxShortField())
			if err != nil {
				return nil, err
			}
			count = c.shortMaxCount() + 1 + int(extra)
		}
		if validate != nil {
			if err := validate(len(result) + count); err != nil {
				return nil, err
			}
		}
		for k := 0; k < count; k++ {
			v, err := take(width)
			if err != nil {
				return nil, err
			}
			result = append(result, c.fromZ(v))
		}
	}
	return result, nil
}
