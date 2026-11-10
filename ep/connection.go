package ep

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esiur/esiur-go/core"
	"github.com/esiur/esiur-go/data"
	"github.com/esiur/esiur-go/packet"
	"github.com/esiur/esiur-go/resource"
	"github.com/esiur/esiur-go/security"
)

const recordHeaderSize = 4

type direction uint8

const (
	dirNone direction = iota
	dirInitiator
	dirResponder
)

type reply struct {
	value any
	err   error
}

type pending struct {
	done         chan reply
	onProgress   func(value, maximum int64)
	onWarning    func(code core.ExceptionCode, message string)
	onPropagated func(any)
	onChunk      func(any)
	resolve      bool
}

// RequestHandler answers an inbound request this node does not answer itself. The reply is sent
// with Connection.SendReply / SendError.
type RequestHandler func(c *Connection, action uint8, callbackID uint32, tdu *data.ParsedTdu)

// NotificationHandler receives an inbound notification other than a resource change.
type NotificationHandler func(c *Connection, action uint8, tdu *data.ParsedTdu)

// Connection is one EP session over a socket. The initiator (client) sends an Initialize auth
// packet and waits for the responder's SessionEstablished; the responder (server) answers the
// peer's Initialize. Once the handshake completes, both sides exchange requests (answered by
// replies, matched through a callback id) and notifications.
//
// With a Warehouse the connection also serves the resources it hosts; without one it is a pure
// client.
type Connection struct {
	registry  *data.TypeRegistry
	warehouse *resource.Warehouse
	parser    ParserConfig
	cfg       Config

	// OnRequest answers requests this node does not handle itself.
	OnRequest RequestHandler
	// OnNotification receives notifications other than resource changes.
	OnNotification NotificationHandler

	socket Socket

	inMu    sync.Mutex // inbound processing and handshake state
	buffer  []byte
	pkt     packet.Packet
	authPkt packet.AuthPacket

	sendMu sync.Mutex // the cipher's sequence and the socket's order

	mu              sync.Mutex
	requests        map[uint32]*pending
	callbackCounter uint32
	attached        map[uint32]*RemoteResource
	needed          map[uint32]*RemoteResource
	attaching       map[uint32]*attachCall
	typedefs        map[uint64]*resource.TypeDef
	notifyTail      chan struct{}
	onClose         []func(*Connection)
	localHeaders    map[uint8]any
	remoteHeaders   map[uint8]any
	variables       map[string]any
	localIdentity   string
	remoteIdentity  string
	sessionKey      []byte
	isClosed        bool

	closed    chan struct{}
	callbacks *executor
	hosted    *hostedSession

	// handshake state (inMu)
	authenticated      atomic.Bool
	encryptionActive   atomic.Bool
	sessionEstablished bool
	direction          direction
	hostName           string
	authMode           packet.AuthenticationMode
	encMode            packet.EncryptionMode
	authProvider       security.AuthProvider
	authProtocol       string
	authHandler        security.AuthHandler
	responderIdentity  string
	encProviders       map[string]security.EncryptionProvider
	encOrder           []string
	offeredEncryption  []string
	encProvider        security.EncryptionProvider
	cipher             security.Cipher
	decryptInbound     bool
	ready              chan struct{}
	readyErr           error
	readyOnce          sync.Once
	dlMu               sync.Mutex
	deadline           *time.Timer
	authTimeout        time.Duration
	domain             string
}

type attachCall struct {
	done     chan struct{}
	resource *RemoteResource
	err      error
}

// NewConnection creates a connection; assign it a socket with Assign after starting a
// handshake (or not, for a socket that needs none).
func NewConnection(cfg Config) *Connection {
	parser := DefaultParserConfig()
	if cfg.Parser != nil {
		parser = *cfg.Parser
	}
	timeout := cfg.AuthenticationTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	protocol := cfg.AuthenticationProtocol
	if protocol == "" {
		protocol = security.PasswordProtocol
	}
	c := &Connection{
		registry: cfg.Registry, warehouse: cfg.Warehouse, parser: parser, cfg: cfg,
		requests: map[uint32]*pending{}, attached: map[uint32]*RemoteResource{},
		needed: map[uint32]*RemoteResource{}, attaching: map[uint32]*attachCall{},
		typedefs: map[uint64]*resource.TypeDef{}, localHeaders: map[uint8]any{},
		remoteHeaders: map[uint8]any{}, variables: map[string]any{},
		closed: make(chan struct{}), callbacks: newExecutor(),
		authMode: cfg.AuthenticationMode, encMode: cfg.EncryptionMode,
		authProvider: cfg.AuthenticationProvider, authProtocol: protocol,
		localIdentity: cfg.Identity, responderIdentity: cfg.ResponderIdentity,
		encProviders: map[string]security.EncryptionProvider{},
		authTimeout:  timeout, domain: cfg.Domain,
	}
	for _, p := range cfg.EncryptionProviders {
		c.encProviders[p.Name()] = p
		c.encOrder = append(c.encOrder, p.Name())
	}
	// A connection assigned a socket without a handshake is authenticated.
	c.authenticated.Store(true)
	c.sessionEstablished = true
	if cfg.Warehouse != nil {
		c.hosted = newHostedSession(c, cfg.Warehouse)
	}
	return c
}

// Connect opens a client connection to url (ws://, wss://, ep://, eps:// or tcp://), runs the
// handshake, and returns once the session is established.
func Connect(ctx context.Context, rawURL string, cfg Config) (*Connection, error) {
	endpoint, err := NormalizeEndpoint(rawURL)
	if err != nil {
		return nil, err
	}
	socketURL := WebSocketURL(endpoint)
	u, err := url.Parse(socketURL)
	if err != nil {
		return nil, err
	}
	c := NewConnection(cfg)
	c.hostName = u.Hostname()
	domain := cfg.Domain
	if domain == "" {
		domain = u.Hostname()
	}
	c.StartInitiatorHandshake(domain)
	var socket Socket
	switch u.Scheme {
	case "tcp":
		socket, err = DialTCP(ctx, u.Host)
	case "ws", "wss":
		socket, err = DialWebSocket(ctx, socketURL, c.parser.MaximumEncryptedRecordSize)
	default:
		err = fmt.Errorf("esiur: unsupported EP transport %q", u.Scheme)
	}
	if err != nil {
		c.failReady(core.ManagementError(core.HostNotReachable, "%v", err))
		return nil, err
	}
	c.Assign(socket)
	if err := c.WhenReady(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Assign attaches a socket and routes its events here; an initiator sends its Initialize.
func (c *Connection) Assign(s Socket) {
	c.inMu.Lock()
	c.mu.Lock()
	c.socket = s
	c.mu.Unlock()
	initiate := c.direction == dirInitiator && !c.authenticated.Load()
	c.inMu.Unlock()
	s.Start(c)
	if initiate {
		c.inMu.Lock()
		c.declare()
		c.inMu.Unlock()
	}
}

// StartInitiatorHandshake begins the client-side handshake, which runs once a socket is
// assigned; WhenReady waits for its end.
func (c *Connection) StartInitiatorHandshake(domain string) {
	c.inMu.Lock()
	defer c.inMu.Unlock()
	c.authenticated.Store(false)
	c.sessionEstablished = false
	c.direction = dirInitiator
	if domain != "" {
		c.domain = domain
	}
	c.authHandler = nil
	c.mu.Lock()
	c.remoteHeaders = map[uint8]any{}
	c.localHeaders = map[uint8]any{}
	if c.domain != "" {
		c.localHeaders[packet.HeaderDomain] = c.domain
	}
	c.mu.Unlock()
	c.ready = make(chan struct{})
	c.readyOnce = sync.Once{}
	c.restartDeadline()
}

// StartResponderHandshake begins the server-side handshake: wait for the peer's Initialize.
func (c *Connection) StartResponderHandshake() {
	c.inMu.Lock()
	defer c.inMu.Unlock()
	c.authenticated.Store(false)
	c.sessionEstablished = false
	c.direction = dirResponder
	c.authHandler = nil
	c.mu.Lock()
	c.remoteHeaders = map[uint8]any{}
	c.localHeaders = map[uint8]any{}
	c.localIdentity, c.remoteIdentity, c.sessionKey = "", "", nil
	c.mu.Unlock()
	c.restartDeadline()
}

// WhenReady waits for the handshake to complete.
func (c *Connection) WhenReady(ctx context.Context) error {
	c.inMu.Lock()
	ready := c.ready
	c.inMu.Unlock()
	if ready == nil {
		return nil
	}
	select {
	case <-ready:
		c.inMu.Lock()
		defer c.inMu.Unlock()
		return c.readyErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Connection) succeedReady() {
	if c.ready != nil {
		c.readyOnce.Do(func() { close(c.ready) })
	}
}

func (c *Connection) failReady(err error) {
	if c.ready != nil {
		c.readyOnce.Do(func() { c.readyErr = err; close(c.ready) })
	}
}

// Close closes the connection. Pending requests fail with HostNotReachable.
func (c *Connection) Close() {
	c.cancelDeadline()
	if s := c.sock(); s != nil {
		s.Close()
	} else {
		c.NetworkClose(nil)
	}
}

// Done is closed once the connection has closed.
func (c *Connection) Done() <-chan struct{} { return c.closed }

// OnClose registers f, called once the connection closes.
func (c *Connection) OnClose(f func(*Connection)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onClose = append(c.onClose, f)
}

func (c *Connection) sock() Socket {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.socket
}

// IsConnected reports an established socket.
func (c *Connection) IsConnected() bool {
	s := c.sock()
	return s != nil && s.Established()
}

// IsAuthenticated is true once the handshake has completed.
func (c *Connection) IsAuthenticated() bool { return c.authenticated.Load() }

// IsEncrypted is true once records are protected in both directions.
func (c *Connection) IsEncrypted() bool { return c.encryptionActive.Load() }

// LocalIdentity is the identity this node proved ("" for an anonymous session).
func (c *Connection) LocalIdentity() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localIdentity
}

// RemoteIdentity is the identity the peer proved ("" if it proved none).
func (c *Connection) RemoteIdentity() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteIdentity
}

// SessionKey is the secret the authentication protocol derived, if it derives one.
func (c *Connection) SessionKey() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionKey
}

// RemoteHeaders are the headers of the peer's handshake packets.
func (c *Connection) RemoteHeaders() map[uint8]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[uint8]any, len(c.remoteHeaders))
	for k, v := range c.remoteHeaders {
		out[k] = v
	}
	return out
}

// RemoteLimit is a budget the peer advertised in its headers; 0 when it advertised none.
func (c *Connection) RemoteLimit(header packet.AuthHeader) int {
	c.mu.Lock()
	v := c.remoteHeaders[header]
	c.mu.Unlock()
	if _, isBool := v.(bool); isBool {
		return 0
	}
	if i, ok := data.ToInt64(v); ok && i > 0 {
		return int(i)
	}
	return 0
}

// Session is what is known about the peer: identities, key, headers, encryption state.
func (c *Connection) Session() *security.Session {
	c.mu.Lock()
	s := &security.Session{
		AuthenticationMode: c.authMode, LocalHeaders: c.localHeaders, RemoteHeaders: c.remoteHeaders,
		LocalIdentity: c.localIdentity, RemoteIdentity: c.remoteIdentity, Key: c.sessionKey,
		Variables: c.variables, EncryptionMode: c.encMode,
	}
	c.mu.Unlock()
	s.Authenticated = c.authenticated.Load()
	s.EncryptionActive = c.encryptionActive.Load()
	s.RemoteMaximumPacketSize = c.RemoteLimit(packet.HeaderMaximumPacketSize)
	s.RemoteMaximumAllocationSize = c.RemoteLimit(packet.HeaderMaximumAllocationSize)
	s.RemoteMaximumCollectionItems = c.RemoteLimit(packet.HeaderMaximumCollectionItems)
	s.RemoteMaximumTypeMetadataDepth = c.RemoteLimit(packet.HeaderMaximumTypeMetadataDepth)
	s.RemoteMaximumEncryptedRecordSize = c.RemoteLimit(packet.HeaderMaximumEncryptedRecordSize)
	return s
}

// ---- socket events ------------------------------------------------------------------------

// NetworkClose implements Receiver.
func (c *Connection) NetworkClose(s Socket) {
	c.inMu.Lock()
	if s != nil && s != c.socket {
		c.inMu.Unlock()
		return
	}
	c.cancelDeadline()
	c.failReady(core.ManagementError(core.HostNotReachable, "Connection closed during handshake."))
	wasAuthenticated := c.authenticated.Load()
	c.inMu.Unlock()

	c.mu.Lock()
	if c.isClosed {
		c.mu.Unlock()
		return
	}
	c.isClosed = true
	pendings := c.requests
	c.requests = map[uint32]*pending{}
	c.attached = map[uint32]*RemoteResource{}
	c.needed = map[uint32]*RemoteResource{}
	handlers := append([]func(*Connection){}, c.onClose...)
	c.mu.Unlock()

	if c.hosted != nil {
		c.hosted.close()
	}
	closedErr := core.ManagementError(core.HostNotReachable, "Connection closed.")
	for _, p := range pendings {
		p.done <- reply{err: closedErr}
	}
	if wasAuthenticated {
		if obs, ok := c.authProvider.(security.SessionObserver); ok {
			obs.Logout(c.Session())
		}
	}
	close(c.closed)
	c.callbacks.close()
	for _, h := range handlers {
		func() {
			defer recoverLog("on-close handler")
			h(c)
		}()
	}
}

func recoverLog(what string) {
	if r := recover(); r != nil {
		log.Printf("esiur: %s failed: %v", what, r)
	}
}

// NetworkReceive implements Receiver.
func (c *Connection) NetworkReceive(s Socket, b []byte) {
	c.inMu.Lock()
	defer c.inMu.Unlock()
	if s != c.socket {
		return
	}
	c.buffer = append(c.buffer, b...)
	if err := c.drain(); err != nil {
		if errors.Is(err, data.ErrLimit) {
			log.Printf("esiur: closing a connection after a limit violation: %v", err)
		} else {
			log.Printf("esiur: closing a connection after a protocol violation: %v", err)
		}
		c.socket.Close()
	}
}

func (c *Connection) drain() error {
	// Work on a private copy, so a packet's TDU stays valid while it is handled elsewhere.
	message := c.buffer
	c.buffer = nil
	offset, ends := 0, len(message)
	limit := c.parser.MaximumPacketSize
	defer func() {
		if offset < ends {
			c.buffer = append([]byte(nil), message[offset:]...)
		}
	}()
	for offset < ends && c.socket.Established() {
		switch {
		case c.decryptInbound:
			consumed, err := c.receiveRecord(message, offset, ends)
			if err != nil {
				return err
			}
			if consumed <= 0 {
				return nil
			}
			offset += consumed
		case !c.authenticated.Load():
			consumed, err := c.authPkt.Parse(message, offset, ends, limit)
			if err != nil {
				return err
			}
			if consumed < 0 {
				return nil
			}
			offset += consumed
			c.handleAuthPacket(&c.authPkt)
		default:
			consumed, err := c.pkt.Parse(message, offset, ends, limit)
			if err != nil {
				return err
			}
			if consumed < 0 {
				return nil
			}
			offset += consumed
			p := c.pkt
			if err := c.dispatch(&p); err != nil {
				return err
			}
		}
	}
	return nil
}

// receiveRecord decrypts and dispatches one encrypted record; it returns the bytes consumed,
// or 0 when more are needed.
func (c *Connection) receiveRecord(message []byte, offset, ends int) (int, error) {
	if ends-offset < recordHeaderSize {
		return 0, nil
	}
	length := int(binary.BigEndian.Uint32(message[offset:]))
	if limit := c.parser.MaximumEncryptedRecordSize; limit > 0 && length > limit {
		return 0, &data.ParserError{Message: fmt.Sprintf("An encrypted record of %d bytes exceeds %d.", length, limit), Limit: true}
	}
	total := recordHeaderSize + length
	if ends-offset < total {
		return 0, nil
	}
	plain, err := c.cipher.Decrypt(message[offset+recordHeaderSize : offset+total])
	if err != nil {
		c.failAuthentication(err, true)
		return 0, nil
	}
	return total, c.dispatchPlaintext(plain)
}

// dispatchPlaintext dispatches every packet of a decrypted record. The record arrived whole, so
// a truncated packet is a protocol error.
func (c *Connection) dispatchPlaintext(plain []byte) error {
	offset, ends := 0, len(plain)
	limit := c.parser.MaximumPacketSize
	for offset < ends && c.socket.Established() {
		if !c.authenticated.Load() {
			consumed, err := c.authPkt.Parse(plain, offset, ends, limit)
			if err != nil {
				return err
			}
			if consumed <= 0 {
				return &data.ParserError{Message: "Truncated encrypted auth packet."}
			}
			offset += consumed
			c.handleAuthPacket(&c.authPkt)
		} else {
			consumed, err := c.pkt.Parse(plain, offset, ends, limit)
			if err != nil {
				return err
			}
			if consumed <= 0 {
				return &data.ParserError{Message: "Truncated encrypted packet."}
			}
			offset += consumed
			p := c.pkt
			if err := c.dispatch(&p); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- sending ------------------------------------------------------------------------------

// Send writes raw, already composed bytes to the socket, as one encrypted record once
// encryption is active.
func (c *Connection) Send(message []byte) error {
	s := c.sock()
	if s == nil {
		return core.ManagementError(core.HostNotReachable, "Connection closed.")
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.encryptionActive.Load() && c.cipher != nil {
		if limit := c.RemoteLimit(packet.HeaderMaximumEncryptedRecordSize); limit > 0 && c.encProvider != nil &&
			len(message)+c.encProvider.MaximumRecordOverhead() > limit {
			return core.ManagementError(core.ParserLimitExceeded, "Encrypted record would exceed the peer's advertised %d-byte limit.", limit)
		}
		protected, err := c.cipher.Encrypt(message)
		if err != nil {
			return err
		}
		message = append(binary.BigEndian.AppendUint32(nil, uint32(len(protected))), protected...)
	}
	s.Send(message)
	return nil
}

// Composer is how values are written to this peer.
func (c *Connection) Composer() *data.Composer {
	return &data.Composer{Types: c.registry, Resources: c.composeResource}
}

// Parser is how this connection decodes values.
func (c *Connection) Parser() *data.Parser {
	return &data.Parser{Limits: c.parser.limits(), Types: c.registry}
}

// ComposeValue is one value as a TDU, the way it is written to this peer.
func (c *Connection) ComposeValue(value any) ([]byte, error) { return c.Composer().Compose(value) }

func (c *Connection) composeArgs(args []any) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	var value any = args
	if len(args) == 1 {
		value = args[0]
	}
	tdu, err := c.ComposeValue(value)
	if err != nil {
		return nil, err
	}
	if limit := c.RemoteLimit(packet.HeaderMaximumPacketSize); limit > 0 {
		m, _ := data.MeasureTdu(tdu, 0, len(tdu), 0)
		if m.PayloadLength > limit {
			return nil, core.ManagementError(core.ParserLimitExceeded,
				"Composed packet payload of %d bytes exceeds the peer's advertised %d-byte limit.", m.PayloadLength, limit)
		}
	}
	return tdu, nil
}

// Decode decodes the value of a received packet (nil when it carried none).
func (c *Connection) Decode(tdu *data.ParsedTdu) (any, error) {
	if tdu == nil {
		return nil, nil
	}
	return c.Parser().Decode(tdu)
}

// RequestOptions tune one request.
type RequestOptions struct {
	OnProgress   func(value, maximum int64)
	OnWarning    func(code core.ExceptionCode, message string)
	OnPropagated func(any)
	OnChunk      func(any)
	// KeepReferences leaves the peer's resource references in the result as data.ResourceID
	// instead of attaching them.
	KeepReferences bool
}

// Request sends a request and waits for the peer's answer. No arguments are sent as no value,
// one as itself, several as a list. Resource references in the result are attached and returned
// as *RemoteResource proxies.
func (c *Connection) Request(ctx context.Context, action uint8, args ...any) (any, error) {
	return c.RequestWith(ctx, action, RequestOptions{}, args...)
}

// RequestWith is Request with options.
func (c *Connection) RequestWith(ctx context.Context, action uint8, opts RequestOptions, args ...any) (any, error) {
	if !c.IsConnected() {
		return nil, core.ManagementError(core.HostNotReachable, "Connection is not available.")
	}
	p := &pending{
		done: make(chan reply, 1), onProgress: opts.OnProgress, onWarning: opts.OnWarning,
		onPropagated: opts.OnPropagated, onChunk: opts.OnChunk, resolve: !opts.KeepReferences,
	}
	tdu, err := c.composeArgs(args)
	if err != nil {
		return nil, core.FromError(err)
	}
	c.mu.Lock()
	if c.isClosed {
		c.mu.Unlock()
		return nil, core.ManagementError(core.HostNotReachable, "Connection closed.")
	}
	id := c.nextCallbackIDLocked()
	c.requests[id] = p
	c.mu.Unlock()
	message, err := packet.ComposeRequest(action, id, tdu)
	if err == nil {
		err = c.Send(message)
	}
	if err != nil {
		c.forget(id)
		return nil, core.FromError(err)
	}
	select {
	case r := <-p.done:
		return r.value, r.err
	case <-ctx.Done():
		c.forget(id)
		return nil, ctx.Err()
	}
}

func (c *Connection) forget(id uint32) {
	c.mu.Lock()
	delete(c.requests, id)
	c.mu.Unlock()
}

func (c *Connection) nextCallbackIDLocked() uint32 {
	for {
		c.callbackCounter++
		if c.callbackCounter == 0 {
			c.callbackCounter = 1
		}
		if _, used := c.requests[c.callbackCounter]; !used {
			return c.callbackCounter
		}
	}
}

// SendReply answers a peer's request.
func (c *Connection) SendReply(action uint8, callbackID uint32, args ...any) error {
	tdu, err := c.composeArgs(args)
	if err != nil {
		return err
	}
	message, err := packet.ComposeReply(action, callbackID, tdu)
	if err != nil {
		return err
	}
	return c.Send(message)
}

// SendNotification sends a notification, which expects no reply.
func (c *Connection) SendNotification(action uint8, args ...any) error {
	tdu, err := c.composeArgs(args)
	if err != nil {
		return err
	}
	message, err := packet.ComposeNotification(action, tdu)
	if err != nil {
		return err
	}
	return c.Send(message)
}

// SendError answers a request with an error: Management and Exception end it, Warning does not.
func (c *Connection) SendError(t core.ErrorType, callbackID uint32, code core.ExceptionCode, message string) error {
	action := packet.ReplyWarning
	switch t {
	case core.Management:
		action = packet.ReplyPermissionError
	case core.Exception:
		action = packet.ReplyExecutionError
	}
	return c.SendReply(action, callbackID, int(code), message)
}

// SendProgress reports progress on a request.
func (c *Connection) SendProgress(callbackID uint32, value, maximum int64) error {
	return c.SendReply(packet.ReplyProgress, callbackID, value, maximum)
}

// ---- inbound packets ----------------------------------------------------------------------

func (c *Connection) dispatch(p *packet.Packet) error {
	switch p.Method {
	case packet.MethodReply:
		c.dispatchReply(p.Action, p.CallbackID, p.Tdu)
	case packet.MethodRequest:
		c.processRequest(p.Action, p.CallbackID, p.Tdu)
	case packet.MethodNotification:
		if p.Action == packet.PropertyModified || p.Action == packet.EventOccurred {
			return c.resourceNotification(p.Action, p.Tdu)
		}
		if c.OnNotification != nil {
			action, tdu := p.Action, p.Tdu
			go func() {
				defer recoverLog("notification handler")
				c.OnNotification(c, action, tdu)
			}()
		}
	}
	// Extension packets carry nothing this version understands.
	return nil
}

func (c *Connection) processRequest(action uint8, callbackID uint32, tdu *data.ParsedTdu) {
	if c.hosted != nil && c.hosted.handles(action) {
		c.hosted.run(action, callbackID, tdu)
		return
	}
	if c.OnRequest != nil {
		go func() {
			defer recoverLog("request handler")
			c.OnRequest(c, action, callbackID, tdu)
		}()
		return
	}
	// esiur-ts leaves a request nobody handles unanswered, so the peer waits forever.
	_ = c.SendError(core.Management, callbackID, core.NotImplemented, "This node does not handle that request.")
}

func (c *Connection) dispatchReply(action uint8, callbackID uint32, tdu *data.ParsedTdu) {
	c.mu.Lock()
	p := c.requests[callbackID]
	final := action == packet.ReplyCompleted || action == packet.ReplyPermissionError || action == packet.ReplyExecutionError
	if p != nil && final {
		delete(c.requests, callbackID)
	}
	c.mu.Unlock()
	if p == nil {
		return // abandoned, or already answered
	}
	value, err := c.Decode(tdu)
	if err != nil {
		if !final {
			c.forget(callbackID)
		}
		p.done <- reply{err: decodeFailure(err)}
		return
	}
	switch action {
	case packet.ReplyCompleted:
		if p.resolve && hasRemoteReference(value) {
			go func() {
				resolved, err := c.resolveValue(context.Background(), value)
				p.done <- reply{resolved, err}
			}()
		} else {
			p.done <- reply{value: value}
		}
	case packet.ReplyPermissionError, packet.ReplyExecutionError:
		kind := core.Management
		if action == packet.ReplyExecutionError {
			kind = core.Exception
		}
		code, message := errorFields(value)
		p.done <- reply{err: &core.Error{Type: kind, Code: code, Message: message}}
	case packet.ReplyPropagated:
		if f := p.onPropagated; f != nil {
			c.callbacks.post(func() { f(value) })
		}
	case packet.ReplyChunk:
		if f := p.onChunk; f != nil {
			c.callbacks.post(func() { f(value) })
		}
	case packet.ReplyWarning:
		if f := p.onWarning; f != nil {
			code, message := errorFields(value)
			c.callbacks.post(func() { f(code, message) })
		}
	case packet.ReplyProgress:
		if f := p.onProgress; f != nil {
			values := asList(value)
			c.callbacks.post(func() { f(intAt(values, 0), intAt(values, 1)) })
		}
	}
	// ReplyStream only announces that chunks follow.
}

func decodeFailure(err error) *core.Error {
	code := core.ParseError
	if errors.Is(err, data.ErrLimit) {
		code = core.ParserLimitExceeded
	}
	var e *core.Error
	if errors.As(err, &e) {
		return e
	}
	return &core.Error{Type: core.Management, Code: code, Message: err.Error(), Cause: err}
}

func malformed(format string, args ...any) *core.Error {
	return core.ManagementError(core.ParseError, format, args...)
}

func asList(value any) []any {
	switch v := value.(type) {
	case []any:
		return v
	case data.TypedTuple:
		return v.Values
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Slice && rv.Type() != reflect.TypeOf([]byte(nil)) {
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = rv.Index(i).Interface()
		}
		return out
	}
	return nil
}

func intAt(values []any, i int) int64 {
	if i < len(values) {
		if _, isBool := values[i].(bool); !isBool {
			if v, ok := data.ToInt64(values[i]); ok {
				return v
			}
		}
	}
	return 0
}

func errorFields(value any) (core.ExceptionCode, string) {
	values := asList(value)
	message := ""
	if len(values) > 1 && values[1] != nil {
		message = fmt.Sprint(values[1])
	}
	return core.ExceptionCode(intAt(values, 0)), message
}

func asInt(value any) (int64, error) {
	if _, isBool := value.(bool); !isBool {
		if v, ok := data.ToInt64(value); ok {
			return v, nil
		}
		if u, ok := value.(uint64); ok {
			return int64(u), nil
		}
	}
	return 0, malformed("Expected an integer, received %T.", value)
}

// hasRemoteReference reports whether a decoded value holds a reference to one of the peer's
// resources.
func hasRemoteReference(value any) bool {
	found := false
	walkReferences(value, func(r data.ResourceID) {
		if !r.Local {
			found = true
		}
	})
	return found
}

func walkReferences(value any, f func(data.ResourceID)) {
	switch v := value.(type) {
	case data.ResourceID:
		f(v)
	case []any:
		for _, item := range v {
			walkReferences(item, f)
		}
	case data.Map:
		for _, e := range v {
			walkReferences(e.Key, f)
			walkReferences(e.Value, f)
		}
	case data.TypedTuple:
		walkReferences(v.Values, f)
	default:
		rv := reflect.ValueOf(value)
		if rv.Kind() == reflect.Map && rv.Type().Elem().Kind() == reflect.Interface {
			for _, k := range rv.MapKeys() {
				walkReferences(rv.MapIndex(k).Interface(), f)
			}
		}
	}
}

// ---- callbacks executor -------------------------------------------------------------------

// executor runs user callbacks one at a time, in order, off the connection's reader.
type executor struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queue  []func()
	closed bool
}

func newExecutor() *executor {
	e := &executor{}
	e.cond = sync.NewCond(&e.mu)
	go e.run()
	return e
}

func (e *executor) post(f func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.queue = append(e.queue, f)
	e.cond.Signal()
}

func (e *executor) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	e.cond.Signal()
}

func (e *executor) run() {
	for {
		e.mu.Lock()
		for len(e.queue) == 0 && !e.closed {
			e.cond.Wait()
		}
		if len(e.queue) == 0 {
			e.mu.Unlock()
			return
		}
		f := e.queue[0]
		e.queue = e.queue[1:]
		e.mu.Unlock()
		func() {
			defer recoverLog("listener")
			f()
		}()
	}
}
