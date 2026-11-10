// Package security holds authentication (providers, handlers, sessions and the
// password-sha3-v1 protocol), transport encryption (AES-256-GCM records) and permissions.
package security

import (
	"github.com/esiur/esiur-go/core"
	"github.com/esiur/esiur-go/packet"
)

// AuthenticationMode says which parties prove identity during the handshake.
type AuthenticationMode = packet.AuthenticationMode

// EncryptionMode is the transport encryption mode.
type EncryptionMode = packet.EncryptionMode

// Direction is which side of the exchange a handler plays.
type Direction uint8

const (
	Initiator Direction = 0
	Responder Direction = 1
)

// AuthRuling is what one handler step concluded.
type AuthRuling uint8

const (
	AuthFailed     AuthRuling = 0
	AuthInProgress AuthRuling = 1
	AuthSucceeded  AuthRuling = 2
)

// MaterialType classifies an AuthenticationMaterial.
type MaterialType uint8

const (
	MaterialSecret   MaterialType = 0
	MaterialKey      MaterialType = 1
	MaterialIdentity MaterialType = 2
	MaterialData     MaterialType = 3
)

// Material is one piece of input to an authentication handler.
type Material struct {
	Type  MaterialType
	Value any
}

// AuthContext is what a provider needs to create the handler of one connection.
type AuthContext struct {
	Direction         Direction
	Mode              AuthenticationMode
	Domain            string
	InitiatorIdentity string
	ResponderIdentity string
	Materials         []Material
	HostName          string
}

// AuthResult is the outcome of one handler step. AuthenticationData is what to send to the peer
// (nil for nothing); on success SessionKey is the secret both sides derived.
type AuthResult struct {
	Ruling             AuthRuling
	AuthenticationData any
	LocalIdentity      string
	RemoteIdentity     string
	SessionKey         []byte
	ExceptionCode      core.ExceptionCode
	ExceptionMessage   string
}

// AuthHandler is the per-connection state machine of an authentication protocol.
type AuthHandler interface {
	// Protocol is the protocol's name, as announced in the AuthenticationProtocol header.
	Protocol() string
	// Process takes what the peer sent (nil at the start of the initiator's side) and decides
	// the next step.
	Process(authenticationData any) AuthResult
}

// AuthProvider creates the handlers of one authentication protocol and hears about its
// sessions.
type AuthProvider interface {
	// Name is the protocol's name; peers select a provider by it.
	Name() string
	// CreateHandler returns a handler for one connection, or nil if ctx is not supported.
	CreateHandler(ctx AuthContext) AuthHandler
}

// SessionObserver is optionally implemented by an AuthProvider to hear about sessions.
type SessionObserver interface {
	Login(session *Session)
	Logout(session *Session)
}

// Session is what is known about a peer: the object permissions managers receive.
type Session struct {
	AuthenticationMode AuthenticationMode
	LocalHeaders       map[uint8]any
	RemoteHeaders      map[uint8]any
	// LocalIdentity is the identity this node proved ("" for none).
	LocalIdentity string
	// RemoteIdentity is the identity the peer proved ("" for none).
	RemoteIdentity string
	// Key is the secret derived by the authentication protocol, if it derives one.
	Key           []byte
	Authenticated bool
	// Variables is free-form state for providers and managers; it is shared with the
	// connection.
	Variables      map[string]any
	EncryptionMode EncryptionMode
	// EncryptionActive is true once records are protected in both directions.
	EncryptionActive bool
	// Budgets the peer advertised; 0 means none was advertised.
	RemoteMaximumPacketSize          int
	RemoteMaximumAllocationSize      int
	RemoteMaximumCollectionItems     int
	RemoteMaximumTypeMetadataDepth   int
	RemoteMaximumEncryptedRecordSize int
}
