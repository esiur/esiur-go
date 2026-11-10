// Package packet implements the EP protocol packets (port of esiur-ts net/packets): the
// session packet (Packet) and the authentication-phase packet (AuthPacket).
package packet

// Method is the top two bits of an EP packet header.
type Method uint8

const (
	MethodNotification Method = 0
	MethodRequest      Method = 1
	MethodReply        Method = 2
	MethodExtension    Method = 3
)

// Request actions, in the low five bits of the header.
const (
	// Invoke
	InvokeFunction       uint8 = 0x00
	SetProperty          uint8 = 0x01
	Subscribe            uint8 = 0x02
	Unsubscribe          uint8 = 0x03
	QueryResourceJournal uint8 = 0x04
	// Inquire
	TypeDefIDsByNames   uint8 = 0x08 // request: list of names, reply: list of ids
	TypeDefByID         uint8 = 0x09
	TypeDefByResourceID uint8 = 0x0A
	Query               uint8 = 0x0B
	LinkTypeDefs        uint8 = 0x0C
	Token               uint8 = 0x0D
	GetResourceIDByLink uint8 = 0x0E
	SyncTypeDefs        uint8 = 0x0F // validate cached TypeDefs by name and signature
	// Manage
	AttachResource   uint8 = 0x10
	ReattachResource uint8 = 0x11
	DetachResource   uint8 = 0x12
	CreateResource   uint8 = 0x13
	DeleteResource   uint8 = 0x14
	MoveResource     uint8 = 0x15
	// Static
	KeepAlive          uint8 = 0x18
	ProcedureCall      uint8 = 0x19
	StaticCall         uint8 = 0x1A
	IndirectCall       uint8 = 0x1B
	PullStream         uint8 = 0x1C
	TerminateExecution uint8 = 0x1D
	HaltExecution      uint8 = 0x1E
	ResumeExecution    uint8 = 0x1F
)

// Reply actions, in the low five bits of the header.
const (
	// Success
	ReplyCompleted  uint8 = 0x0
	ReplyPropagated uint8 = 0x1
	ReplyStream     uint8 = 0x2
	// Error
	ReplyPermissionError uint8 = 0x4
	ReplyExecutionError  uint8 = 0x5
	// Partial
	ReplyProgress uint8 = 0x8
	ReplyChunk    uint8 = 0x9
	ReplyWarning  uint8 = 0xA
)

// Notification actions, in the low five bits of the header.
const (
	PropertyModified   uint8 = 0x0
	EventOccurred      uint8 = 0x1
	ResourceDestroyed  uint8 = 0x8
	ResourceReassigned uint8 = 0x9
	ResourceMoved      uint8 = 0xA
	SystemFailure      uint8 = 0xB
)

// AuthCommand is the top two bits of an authentication packet header.
type AuthCommand uint8

const (
	AuthInitialize  AuthCommand = 0
	AuthAcknowledge AuthCommand = 1
	AuthAction      AuthCommand = 2
	AuthEvent       AuthCommand = 3
)

// AuthMethod is an authentication packet method. Its top two bits repeat the AuthCommand; for
// example SessionEstablished (0x47) is an acknowledge.
type AuthMethod uint8

const (
	// Initialize
	MethodInitialize AuthMethod = 0x00
	// Actions
	Handshake      AuthMethod = 0x80
	FinalHandshake AuthMethod = 0x81
	// Acknowledgements
	Denied                    AuthMethod = 0x40
	NotSupported              AuthMethod = 0x41
	TrySupported              AuthMethod = 0x42
	Retry                     AuthMethod = 0x43
	ProceedToHandshake        AuthMethod = 0x44
	ProceedToFinalHandshake   AuthMethod = 0x45
	ProceedToEstablishSession AuthMethod = 0x46
	SessionEstablished        AuthMethod = 0x47
	// Events
	Established           AuthMethod = 0xC0
	ErrorTerminate        AuthMethod = 0xC1
	ErrorMustEncrypt      AuthMethod = 0xC2
	ErrorRetry            AuthMethod = 0xC3
	IndicationEstablished AuthMethod = 0xC8
	IAuthPlain            AuthMethod = 0xD0
	IAuthHashed           AuthMethod = 0xD1
	IAuthEncrypted        AuthMethod = 0xD2
)

// AuthHeader is a key of the TypedMap<UInt8, Dynamic> an authentication packet carries.
type AuthHeader = uint8

const (
	HeaderVersion                             AuthHeader = 0
	HeaderDomain                              AuthHeader = 1
	HeaderSupportedAuthentications            AuthHeader = 2
	HeaderSupportedHashAlgorithms             AuthHeader = 3
	HeaderSupportedCiphers                    AuthHeader = 4
	HeaderSupportedCompression                AuthHeader = 5
	HeaderSupportedMultiFactorAuthentications AuthHeader = 6
	HeaderCipherType                          AuthHeader = 7
	HeaderCipherKey                           AuthHeader = 8
	HeaderSoftwareIdentity                    AuthHeader = 9
	HeaderReferrer                            AuthHeader = 10
	HeaderTime                                AuthHeader = 11
	HeaderIPAddress                           AuthHeader = 12
	HeaderIdentity                            AuthHeader = 13
	HeaderAuthenticationProtocol              AuthHeader = 14
	HeaderAuthenticationData                  AuthHeader = 15
	HeaderErrorMessage                        AuthHeader = 16
	// HeaderCipherNonce is a fresh public nonce used with the authenticated session key to
	// derive unique per-connection encryption keys.
	HeaderCipherNonce AuthHeader = 17
	// Parser budgets this peer accepts.
	HeaderMaximumPacketSize          AuthHeader = 18
	HeaderMaximumAllocationSize      AuthHeader = 19
	HeaderMaximumCollectionItems     AuthHeader = 20
	HeaderMaximumTypeMetadataDepth   AuthHeader = 21
	HeaderMaximumEncryptedRecordSize AuthHeader = 22
)

// AuthenticationMode says which parties prove identity during the handshake.
type AuthenticationMode uint8

const (
	AuthNone                AuthenticationMode = 0
	AuthInitializerIdentity AuthenticationMode = 1
	AuthResponderIdentity   AuthenticationMode = 2
	AuthDualIdentity        AuthenticationMode = 3
)

// EncryptionMode is the transport encryption mode.
type EncryptionMode uint8

const (
	EncryptNone                     EncryptionMode = 0
	EncryptWithSessionKey           EncryptionMode = 1
	EncryptWithSessionKeyAndAddress EncryptionMode = 2
)
