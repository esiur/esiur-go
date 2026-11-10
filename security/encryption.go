package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/esiur/esiur-go/packet"
)

// EncryptionContext is what the handshake settled on, from which a cipher is created. Initiator
// and responder values keep their protocol roles whichever peer creates the cipher.
type EncryptionContext struct {
	// Key is the shared secret the authentication protocol derived.
	Key []byte
	// Direction is the role of the peer creating the cipher.
	Direction Direction
	Mode      EncryptionMode
	// Protocol is the negotiated encryption protocol name.
	Protocol string
	// OfferedProtocols are the protocols the initiator offered, in wire order.
	OfferedProtocols       []string
	AuthenticationMode     AuthenticationMode
	AuthenticationProtocol string
	Domain                 string
	InitiatorNonce         []byte
	ResponderNonce         []byte
}

// Cipher is a per-session record cipher. It keeps the record sequence, so it protects exactly
// one connection and one direction pair.
type Cipher interface {
	Encrypt(data []byte) ([]byte, error)
	// Decrypt authenticates and decrypts a record.
	Decrypt(data []byte) ([]byte, error)
}

// EncryptionProvider creates the cipher of a session.
type EncryptionProvider interface {
	// Name is the name peers negotiate the provider by.
	Name() string
	// MaximumRecordOverhead is the most bytes Encrypt adds to one record.
	MaximumRecordOverhead() int
	CreateCipher(ctx EncryptionContext) (Cipher, error)
}

const (
	aesKeySize        = 32
	aesNoncePrefix    = 4
	aesSequenceSize   = 8
	aesTagSize        = 16
	aesRecordOverhead = aesSequenceSize + aesTagSize
	minSharedKey      = 16
	maxSharedKey      = 1024
	minPeerNonce      = 16
	maxPeerNonce      = 64
	aesContextLabel   = "esiur/ep/aes-256-gcm/context/v3"
	i2r               = "initiator-to-responder"
	r2i               = "responder-to-initiator"
)

// AesGcmName is the negotiated name of the AES-256-GCM provider.
const AesGcmName = "aes-gcm"

// AesGcm creates AES-256-GCM record ciphers, negotiated as "aes-gcm".
type AesGcm struct{}

func (AesGcm) Name() string               { return AesGcmName }
func (AesGcm) MaximumRecordOverhead() int { return aesRecordOverhead }
func (AesGcm) CreateCipher(ctx EncryptionContext) (Cipher, error) {
	return NewAesGcmCipher(ctx)
}

// AesGcmCipher protects records as [8-byte big-endian sequence][ciphertext][16-byte tag]. The
// record length and the sequence are authenticated as associated data, and the sequence is both
// implicit state and an explicit field, so a replayed, dropped or reordered record fails closed.
type AesGcmCipher struct {
	mu                         sync.Mutex
	send, receive              cipher.AEAD
	sendPrefix, receivePrefix  []byte
	sendSequence, recvSequence uint64
}

func label(direction, purpose string) string {
	return "esiur/ep/aes-256-gcm/v1/" + direction + "/" + purpose
}

func derive(key, salt []byte, info string, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, key, salt, info, length)
}

func newAead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewAesGcmCipher derives per-direction keys (HKDF-SHA256 over the negotiated transcript).
func NewAesGcmCipher(ctx EncryptionContext) (*AesGcmCipher, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	send, receive := i2r, r2i
	if ctx.Direction != Initiator {
		send, receive = r2i, i2r
	}
	salt := contextSalt(ctx)
	c := &AesGcmCipher{}
	for _, step := range []struct {
		dir, purpose string
		size         int
		into         *[]byte
	}{
		{send, "nonce", aesNoncePrefix, &c.sendPrefix},
		{receive, "nonce", aesNoncePrefix, &c.receivePrefix},
	} {
		v, err := derive(ctx.Key, salt, label(step.dir, step.purpose), step.size)
		if err != nil {
			return nil, err
		}
		*step.into = v
	}
	sendKey, err := derive(ctx.Key, salt, label(send, "key"), aesKeySize)
	if err != nil {
		return nil, err
	}
	receiveKey, err := derive(ctx.Key, salt, label(receive, "key"), aesKeySize)
	if err != nil {
		return nil, err
	}
	if c.send, err = newAead(sendKey); err != nil {
		return nil, err
	}
	if c.receive, err = newAead(receiveKey); err != nil {
		return nil, err
	}
	return c, nil
}

func aad(recordLength int, sequence uint64) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(recordLength))
	return binary.BigEndian.AppendUint64(b, sequence)
}

func (c *AesGcmCipher) Encrypt(data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendSequence == ^uint64(0) {
		return nil, errors.New("esiur: the AES-GCM send sequence is exhausted")
	}
	header := binary.BigEndian.AppendUint64(nil, c.sendSequence)
	nonce := append(append([]byte{}, c.sendPrefix...), header...)
	out := c.send.Seal(header, nonce, data, aad(len(data)+aesRecordOverhead, c.sendSequence))
	c.sendSequence++
	return out, nil
}

func (c *AesGcmCipher) Decrypt(data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(data) < aesRecordOverhead {
		return nil, errors.New("esiur: the AES-GCM record is truncated")
	}
	sequence := binary.BigEndian.Uint64(data)
	if sequence != c.recvSequence {
		return nil, errors.New("esiur: the AES-GCM record sequence is invalid")
	}
	if c.recvSequence == ^uint64(0) {
		return nil, errors.New("esiur: the AES-GCM receive sequence is exhausted")
	}
	nonce := append(append([]byte{}, c.receivePrefix...), data[:aesSequenceSize]...)
	plain, err := c.receive.Open(nil, nonce, data[aesSequenceSize:], aad(len(data), sequence))
	if err != nil {
		return nil, errors.New("esiur: AES-GCM record authentication failed")
	}
	c.recvSequence++
	return plain, nil
}

func lengthPrefixed(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

// contextSalt is SHA-256 over an ordered, length-prefixed transcript of every negotiated field.
func contextSalt(ctx EncryptionContext) []byte {
	h := sha256.New()
	h.Write([]byte(aesContextLabel))
	h.Write([]byte{byte(ctx.AuthenticationMode)})
	h.Write(lengthPrefixed([]byte(ctx.AuthenticationProtocol)))
	h.Write(lengthPrefixed([]byte(ctx.Domain)))
	h.Write([]byte{byte(ctx.Mode)})
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(ctx.OfferedProtocols))))
	for _, p := range ctx.OfferedProtocols {
		h.Write(lengthPrefixed([]byte(p)))
	}
	h.Write(lengthPrefixed([]byte(ctx.Protocol)))
	h.Write(lengthPrefixed(ctx.InitiatorNonce))
	h.Write(lengthPrefixed(ctx.ResponderNonce))
	return h.Sum(nil)
}

func validateContext(ctx EncryptionContext) error {
	if len(ctx.Key) < minSharedKey || len(ctx.Key) > maxSharedKey {
		return fmt.Errorf("esiur: the shared key must contain between %d and %d bytes", minSharedKey, maxSharedKey)
	}
	for name, nonce := range map[string][]byte{"initiator nonce": ctx.InitiatorNonce, "responder nonce": ctx.ResponderNonce} {
		if len(nonce) < minPeerNonce || len(nonce) > maxPeerNonce {
			return fmt.Errorf("esiur: the %s must contain between %d and %d bytes", name, minPeerNonce, maxPeerNonce)
		}
	}
	switch {
	case ctx.Mode == packet.EncryptNone:
		return errors.New("esiur: AES-GCM requires an encrypted session mode")
	case ctx.Mode != packet.EncryptWithSessionKey:
		return errors.New("esiur: address-bound encryption is not supported")
	case strings.TrimSpace(ctx.Protocol) == "":
		return errors.New("esiur: a negotiated encryption protocol is required")
	case len(ctx.OfferedProtocols) == 0 || slices.ContainsFunc(ctx.OfferedProtocols, func(p string) bool { return strings.TrimSpace(p) == "" }):
		return errors.New("esiur: the initiator's encryption offer is required")
	case !slices.Contains(ctx.OfferedProtocols, ctx.Protocol):
		return errors.New("esiur: the selected encryption protocol was not offered")
	case ctx.AuthenticationMode == packet.AuthNone:
		return errors.New("esiur: AES-GCM requires an authenticated session")
	case strings.TrimSpace(ctx.AuthenticationProtocol) == "":
		return errors.New("esiur: a negotiated authentication protocol is required")
	}
	return nil
}
