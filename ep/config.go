package ep

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/esiur/esiur-go/data"
	"github.com/esiur/esiur-go/packet"
	"github.com/esiur/esiur-go/resource"
	"github.com/esiur/esiur-go/security"
)

// DefaultPort is the native EP port used when an endpoint omits its port.
const DefaultPort = 51018

// ParserConfig is the budget a node applies to what it receives. Each value is sent to the peer
// during the handshake, so the peer refuses to compose anything this node would reject. Zero
// disables a limit.
type ParserConfig struct {
	MaximumPacketSize          int
	MaximumAllocationSize      int
	MaximumCollectionItems     int
	MaximumTypeMetadataDepth   int
	MaximumEncryptedRecordSize int
}

// DefaultParserConfig returns the esiur-dotnet defaults.
func DefaultParserConfig() ParserConfig {
	return ParserConfig{
		MaximumPacketSize:          data.DefaultMaximumPayloadLength,
		MaximumAllocationSize:      data.DefaultMaximumAllocationSize,
		MaximumCollectionItems:     data.DefaultMaximumCollectionItems,
		MaximumTypeMetadataDepth:   data.DefaultMaximumTypeMetadataDepth,
		MaximumEncryptedRecordSize: data.DefaultMaximumPayloadLength + 1024,
	}
}

func (p ParserConfig) limits() data.Limits {
	return data.Limits{
		MaximumPayloadLength:     p.MaximumPacketSize,
		MaximumCollectionItems:   p.MaximumCollectionItems,
		MaximumAllocationSize:    p.MaximumAllocationSize,
		MaximumTypeMetadataDepth: p.MaximumTypeMetadataDepth,
	}
}

// Config configures a Connection. The zero value is an anonymous client with default limits.
type Config struct {
	// Registry holds the record and enum definitions used to encode and decode values.
	Registry *data.TypeRegistry
	// Parser is the receive budget; the zero value means DefaultParserConfig.
	Parser *ParserConfig
	Domain string
	// DenyAnonymous makes a responder refuse peers that do not authenticate.
	DenyAnonymous bool
	// AuthenticationTimeout is the longest the handshake may take; 0 means 30 seconds and a
	// negative value disables the deadline.
	AuthenticationTimeout time.Duration
	// Warehouse holds the resources this node serves to the peer (nil for a pure client). Its
	// authentication and encryption providers are used too.
	Warehouse *resource.Warehouse

	AuthenticationMode packet.AuthenticationMode
	EncryptionMode     packet.EncryptionMode
	// AuthenticationProvider is used by an initiator (or a responder whose warehouse lacks it).
	AuthenticationProvider security.AuthProvider
	// AuthenticationProtocol names the protocol an initiator asks for (default
	// "password-sha3-v1").
	AuthenticationProtocol string
	// Identity is what an initiator proves; ResponderIdentity the responder identity it
	// expects to be proved.
	Identity, ResponderIdentity string
	EncryptionProviders         []security.EncryptionProvider
}

// NormalizeEndpoint validates an endpoint and adds DefaultPort when it has no port. Explicit
// ports are kept; http(s) URLs are returned unchanged.
func NormalizeEndpoint(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", fmt.Errorf("esiur: invalid EP endpoint: %s", value)
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		return value, nil
	}
	if u.Port() == "" {
		u.Host = u.Host + ":" + strconv.Itoa(DefaultPort)
		return u.String(), nil
	}
	if p, err := strconv.Atoi(u.Port()); err != nil || p <= 0 || p > 65535 {
		return "", fmt.Errorf("esiur: EP endpoint ports must be from 1 through 65535: %s", value)
	}
	return value, nil
}

// WebSocketURL is the ws/wss form of an ep/eps endpoint; other schemes are unchanged.
func WebSocketURL(value string) string {
	switch {
	case strings.HasPrefix(value, "ep://"):
		return "ws://" + value[len("ep://"):]
	case strings.HasPrefix(value, "eps://"):
		return "wss://" + value[len("eps://"):]
	}
	return value
}
