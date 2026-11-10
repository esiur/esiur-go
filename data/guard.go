// Package data is the Esiur wire data layer: TDU framing, type representation units (Tru),
// the value codec, typed collections, indexed structures and type definitions.
//
// It is a port of esiur-ts (data/*) and is byte-compatible with it and with esiur-dotnet.
package data

import (
	"errors"
	"fmt"
)

// Parser budgets. The defaults match esiur-dotnet and esiur-ts.
const (
	DefaultMaximumPayloadLength     = 8 * 1024 * 1024
	DefaultMaximumAllocationSize    = 4 * 1024 * 1024
	DefaultMaximumCollectionItems   = 65_536
	DefaultMaximumTypeMetadataDepth = 64
	DefaultMaximumValueDepth        = 64
)

var (
	// ErrParse matches every error that reports bytes that are not a valid Esiur value.
	ErrParse = errors.New("esiur: invalid value")
	// ErrLimit matches errors that report a declared size beyond a configured parser budget.
	ErrLimit = errors.New("esiur: parser limit exceeded")
)

// ParserError reports malformed input, or (Limit set) input beyond a parser budget.
type ParserError struct {
	Message string
	Limit   bool
}

func (e *ParserError) Error() string { return e.Message }

// Is lets errors.Is match ErrParse for every parser error and ErrLimit for limit errors.
func (e *ParserError) Is(target error) bool {
	return target == ErrParse || (e.Limit && target == ErrLimit)
}

func parseErr(format string, args ...any) error {
	return &ParserError{Message: fmt.Sprintf(format, args...)}
}

func limitErr(format string, args ...any) error {
	return &ParserError{Message: fmt.Sprintf(format, args...), Limit: true}
}

// Limits are the parser budgets applied while decoding. A non-positive value disables a limit.
type Limits struct {
	MaximumPayloadLength     int
	MaximumCollectionItems   int
	MaximumAllocationSize    int
	MaximumTypeMetadataDepth int
}

// DefaultLimits returns the esiur-dotnet defaults.
func DefaultLimits() Limits {
	return Limits{
		MaximumPayloadLength:     DefaultMaximumPayloadLength,
		MaximumCollectionItems:   DefaultMaximumCollectionItems,
		MaximumAllocationSize:    DefaultMaximumAllocationSize,
		MaximumTypeMetadataDepth: DefaultMaximumTypeMetadataDepth,
	}
}

// EnsurePacketSize rejects an oversized length declaration before anything is allocated or
// awaited.
func EnsurePacketSize(declared uint64, maximum int) error {
	if maximum > 0 && declared > uint64(maximum) {
		return limitErr("Declared packet payload of %d bytes exceeds the %d-byte limit.", declared, maximum)
	}
	return nil
}

func ensureCollectionCount(count, maximum int) error {
	if maximum > 0 && count > maximum {
		return limitErr("Collection of %d items exceeds the %d-item limit.", count, maximum)
	}
	return nil
}

func ensureAllocation(size, maximum int, kind string) error {
	if maximum > 0 && size > maximum {
		return limitErr("Decoded %s allocation of %d bytes exceeds the %d-byte limit.", kind, size, maximum)
	}
	return nil
}

func ensureTypeMetadataDepth(depth, maximum int) error {
	if maximum > 0 && depth > maximum {
		return limitErr("TRU type metadata depth of %d exceeds the configured limit of %d.", depth, maximum)
	}
	return nil
}
