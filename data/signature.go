package data

import (
	"crypto/sha256"
	"encoding/binary"
)

// Name64 is the first 8 bytes of SHA-256(UTF-8(name)), little endian.
func Name64(name string) uint64 {
	sum := sha256.Sum256([]byte(name))
	return binary.LittleEndian.Uint64(sum[:8])
}

// SignatureOf is the signature of already composed canonical bytes; zero is reserved for
// "unknown", so a zero hash becomes 1.
func SignatureOf(canonical []byte) uint64 {
	sum := sha256.Sum256(canonical)
	if s := binary.LittleEndian.Uint64(sum[:8]); s != 0 {
		return s
	}
	return 1
}

// TypeDefSignature is the id-independent signature of info (esiur-ts computeTypeDefSignature):
// a hash of its normal wire encoding with its own id zeroed and every type reference written as
// the hash of the referenced type's name, so two nodes that assigned different ids to the same
// contract agree on it. nameOf maps a TypeDef id (a reference, or the parent) to its type's
// name; a parent it cannot name is dropped from the hash.
func TypeDefSignature(info *TypeDefInfo, nameOf NameOf) (uint64, error) {
	canonical := *info
	canonical.ID = 0
	canonical.Signature = nil
	if canonical.Parent != nil {
		if name, err := nameOf(*canonical.Parent); err == nil {
			h := Name64(name)
			canonical.Parent = &h
		} else {
			canonical.Parent = nil
		}
	}
	composed, err := (&Composer{NameOf: nameOf}).Compose(&canonical)
	if err != nil {
		return 0, err
	}
	return SignatureOf(composed), nil
}
