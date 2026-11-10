package ep

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/esiur/esiur-go/core"
	"github.com/esiur/esiur-go/data"
	"github.com/esiur/esiur-go/packet"
	"github.com/esiur/esiur-go/security"
)

// Handshake code runs on the reader goroutine (or the deadline timer) with inMu held.

func (c *Connection) limitHeaders() map[uint8]any {
	p := c.parser
	return map[uint8]any{
		packet.HeaderMaximumPacketSize:          p.MaximumPacketSize,
		packet.HeaderMaximumAllocationSize:      p.MaximumAllocationSize,
		packet.HeaderMaximumCollectionItems:     p.MaximumCollectionItems,
		packet.HeaderMaximumTypeMetadataDepth:   p.MaximumTypeMetadataDepth,
		packet.HeaderMaximumEncryptedRecordSize: p.MaximumEncryptedRecordSize,
	}
}

// headersWithLocal is the limits plus a copy of the local headers.
func (c *Connection) headersWithLocal() map[uint8]any {
	h := c.limitHeaders()
	c.mu.Lock()
	for k, v := range c.localHeaders {
		h[k] = v
	}
	c.mu.Unlock()
	return h
}

func (c *Connection) setLocalHeader(key uint8, value any) {
	c.mu.Lock()
	c.localHeaders[key] = value
	c.mu.Unlock()
}

func (c *Connection) localHeader(key uint8) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localHeaders[key]
}

func (c *Connection) remoteHeader(key uint8) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteHeaders[key]
}

func (c *Connection) composeAuthHeaders(headers map[uint8]any) ([]byte, error) {
	keys := make([]int, 0, len(headers))
	for k := range headers {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	entries := make(data.Map, len(keys))
	for i, k := range keys {
		entries[i] = data.MapEntry{Key: uint8(k), Value: headers[uint8(k)]}
	}
	return (&data.Composer{Types: c.registry}).Compose(data.TypedMap{Key: data.T.U8, Value: data.T.Dynamic, Entries: entries})
}

func (c *Connection) sendAuthHeaders(method packet.AuthMethod, headers map[uint8]any) error {
	tdu, err := c.composeAuthHeaders(headers)
	if err != nil {
		return err
	}
	message, err := packet.ComposeMethod(method, tdu)
	if err != nil {
		return err
	}
	return c.Send(message)
}

func (c *Connection) sendAuthData(method packet.AuthMethod, value any) error {
	var tdu []byte
	if value != nil {
		var err error
		if tdu, err = (&data.Composer{Types: c.registry}).Compose(value); err != nil {
			return err
		}
	}
	message, err := packet.ComposeMethod(method, tdu)
	if err != nil {
		return err
	}
	return c.Send(message)
}

// parseAuthHeaders reads the headers of an auth packet, and the authentication data among them.
func (c *Connection) parseAuthHeaders(p *packet.AuthPacket) (map[uint8]any, any, error) {
	value, err := c.Decode(p.Tdu)
	if err != nil {
		return nil, nil, err
	}
	if value == nil {
		return map[uint8]any{}, nil, nil
	}
	entries, ok := data.MapEntries(value)
	if !ok {
		return nil, nil, malformed("Authentication headers must be a map.")
	}
	headers := make(map[uint8]any, len(entries))
	for _, e := range entries {
		k, ok := data.ToInt64(e.Key)
		if !ok || k < 0 || k > 255 {
			return nil, nil, malformed("Authentication header keys must be bytes.")
		}
		headers[uint8(k)] = e.Value
	}
	authData := headers[packet.HeaderAuthenticationData]
	delete(headers, packet.HeaderAuthenticationData)
	return headers, authData, nil
}

func (c *Connection) setRemoteHeaders(h map[uint8]any) {
	c.mu.Lock()
	c.remoteHeaders = h
	c.mu.Unlock()
}

func (c *Connection) readAuthErrorMessage(p *packet.AuthPacket) string {
	value, err := c.Decode(p.Tdu)
	if err != nil {
		return "Authentication error."
	}
	if s, ok := value.(string); ok {
		return s
	}
	if entries, ok := data.MapEntries(value); ok {
		for _, e := range entries {
			if k, ok := data.ToInt64(e.Key); ok && k == int64(packet.HeaderErrorMessage) && e.Value != nil {
				return fmt.Sprint(e.Value)
			}
		}
	}
	return "Authentication error."
}

// declare sends the initiator's Initialize packet: the limits, and when asked for the encryption
// offer and the first step of the authentication.
func (c *Connection) declare() {
	err := func() error {
		headers := c.headersWithLocal()
		if c.domain != "" {
			headers[packet.HeaderDomain] = c.domain
		}
		if c.encMode != packet.EncryptNone {
			if err := c.prepareEncryptionOffer(headers); err != nil {
				return err
			}
		}
		if c.authMode != packet.AuthNone {
			handler, err := c.initiatorHandler()
			if err != nil {
				return err
			}
			first := handler.Process(nil)
			if first.Ruling == security.AuthFailed {
				return core.ManagementError(core.AccessDenied, "Authentication failed.")
			}
			headers[packet.HeaderAuthenticationProtocol] = handler.Protocol()
			headers[packet.HeaderAuthenticationData] = first.AuthenticationData
		}
		tdu, err := c.composeAuthHeaders(headers)
		if err != nil {
			return err
		}
		message, err := packet.ComposeInitialize(c.authMode, c.encMode, tdu)
		if err != nil {
			return err
		}
		return c.Send(message)
	}()
	if err != nil {
		c.failAuthentication(err, false)
	}
}

// ---- encryption negotiation ---------------------------------------------------------------

func (c *Connection) encryptionNames() []string {
	names := append([]string(nil), c.encOrder...)
	if c.warehouse != nil {
		for _, n := range c.warehouse.EncryptionProviderNames() {
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	if len(names) == 0 && c.direction == dirInitiator {
		c.encProviders[security.AesGcmName] = security.AesGcm{}
		c.encOrder = []string{security.AesGcmName}
		names = []string{security.AesGcmName}
	}
	return names
}

func (c *Connection) encryptionProvider(name string) security.EncryptionProvider {
	if p := c.encProviders[name]; p != nil {
		return p
	}
	if c.warehouse != nil {
		return c.warehouse.EncryptionProvider(name)
	}
	return nil
}

func nonce() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func stringsToAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func anyStrings(value any) []string {
	var out []string
	for _, item := range asList(value) {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func validNonce(value any) bool {
	b, ok := value.([]byte)
	return ok && len(b) >= 16 && len(b) <= 64
}

// prepareEncryptionOffer (initiator) offers the supported cipher names and a fresh nonce.
func (c *Connection) prepareEncryptionOffer(headers map[uint8]any) error {
	if c.authMode == packet.AuthNone {
		return errors.New("esiur: session-key encryption requires an authenticated session")
	}
	if c.encMode != packet.EncryptWithSessionKey {
		return fmt.Errorf("esiur: unsupported encryption mode %d", c.encMode)
	}
	var offered []string
	for _, n := range c.encryptionNames() {
		if c.encryptionProvider(n) != nil {
			offered = append(offered, n)
		}
	}
	if len(offered) == 0 {
		return errors.New("esiur: encryption was requested but none of the offered providers are registered")
	}
	c.offeredEncryption = offered
	n := nonce()
	headers[packet.HeaderSupportedCiphers] = stringsToAny(offered)
	headers[packet.HeaderCipherNonce] = n
	c.mu.Lock()
	c.localHeaders[packet.HeaderSupportedCiphers] = stringsToAny(offered)
	c.localHeaders[packet.HeaderCipherNonce] = n
	delete(c.localHeaders, packet.HeaderCipherType)
	c.mu.Unlock()
	return nil
}

// negotiateEncryption (responder) picks an offered cipher this node has and answers with it and
// a nonce.
func (c *Connection) negotiateEncryption(p *packet.AuthPacket, local map[uint8]any) bool {
	requested := p.EncryptionMode
	if requested == packet.EncryptNone {
		c.encMode = packet.EncryptNone
		return true
	}
	if requested != packet.EncryptWithSessionKey {
		return c.rejectEncryption("The requested encryption mode is not supported.")
	}
	c.encMode = packet.EncryptWithSessionKey
	if p.AuthMode == packet.AuthNone {
		return c.rejectEncryption("Session-key encryption requires authentication.")
	}
	selected := ""
	for _, n := range anyStrings(c.remoteHeader(packet.HeaderSupportedCiphers)) {
		if c.encryptionProvider(n) != nil {
			selected = n
			break
		}
	}
	if selected == "" {
		return c.rejectEncryption("No mutually supported encryption provider is available.")
	}
	if !validNonce(c.remoteHeader(packet.HeaderCipherNonce)) {
		return c.rejectEncryption("The initiator did not supply a valid cipher nonce.")
	}
	c.encProvider = c.encryptionProvider(selected)
	var supported []string
	for _, n := range c.encryptionNames() {
		if c.encryptionProvider(n) != nil {
			supported = append(supported, n)
		}
	}
	n := nonce()
	c.mu.Lock()
	for _, target := range []map[uint8]any{c.localHeaders, local} {
		target[packet.HeaderSupportedCiphers] = stringsToAny(supported)
		target[packet.HeaderCipherType] = selected
		target[packet.HeaderCipherNonce] = n
	}
	c.mu.Unlock()
	return true
}

// acceptEncryption (initiator) takes the responder's cipher selection from its headers.
func (c *Connection) acceptEncryption() bool {
	selectedValue := c.remoteHeader(packet.HeaderCipherType)
	if c.encMode == packet.EncryptNone {
		return selectedValue == nil || c.rejectEncryption("The responder selected encryption that was not requested.")
	}
	selected, ok := selectedValue.(string)
	if !ok || strings.TrimSpace(selected) == "" || !slices.Contains(c.offeredEncryption, selected) {
		return c.rejectEncryption("The responder did not select an offered provider.")
	}
	if !validNonce(c.remoteHeader(packet.HeaderCipherNonce)) {
		return c.rejectEncryption("The responder did not supply a valid cipher nonce.")
	}
	provider := c.encryptionProvider(selected)
	if provider == nil {
		return c.rejectEncryption(fmt.Sprintf("Encryption provider `%s` is not registered locally.", selected))
	}
	c.encProvider = provider
	return true
}

func (c *Connection) rejectEncryption(message string) bool {
	_ = c.sendAuthData(packet.ErrorMustEncrypt, message)
	c.failAuthentication(errors.New(message), true)
	return false
}

// startEncryption derives the session cipher and turns record protection on, both directions.
func (c *Connection) startEncryption() error {
	if c.cipher != nil {
		return nil
	}
	c.mu.Lock()
	key := c.sessionKey
	local, remote := c.localHeaders, c.remoteHeaders
	c.mu.Unlock()
	if len(key) == 0 {
		return errors.New("esiur: the authentication provider did not derive a session key")
	}
	if c.encProvider == nil {
		return errors.New("esiur: no encryption provider was negotiated")
	}
	initiator := c.direction == dirInitiator
	initiatorNonce, responderNonce := local[packet.HeaderCipherNonce], remote[packet.HeaderCipherNonce]
	if !initiator {
		initiatorNonce, responderNonce = responderNonce, initiatorNonce
	}
	in, ok1 := initiatorNonce.([]byte)
	rn, ok2 := responderNonce.([]byte)
	if !ok1 || !ok2 {
		return errors.New("esiur: missing negotiated cipher nonce")
	}
	ctx := security.EncryptionContext{
		Key: key, Mode: c.encMode, AuthenticationMode: c.authMode,
		InitiatorNonce: in, ResponderNonce: rn,
	}
	if initiator {
		ctx.Direction = security.Initiator
		ctx.OfferedProtocols = c.offeredEncryption
		if c.authHandler != nil {
			ctx.AuthenticationProtocol = c.authHandler.Protocol()
		}
		ctx.Protocol = fmt.Sprint(remote[packet.HeaderCipherType])
		ctx.Domain = c.domain
	} else {
		ctx.Direction = security.Responder
		ctx.OfferedProtocols = anyStrings(remote[packet.HeaderSupportedCiphers])
		ctx.AuthenticationProtocol, _ = remote[packet.HeaderAuthenticationProtocol].(string)
		ctx.Protocol = fmt.Sprint(local[packet.HeaderCipherType])
		ctx.Domain, _ = remote[packet.HeaderDomain].(string)
	}
	cipher, err := c.encProvider.CreateCipher(ctx)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	c.cipher = cipher
	c.encryptionActive.Store(true)
	c.sendMu.Unlock()
	c.decryptInbound = true
	return nil
}

// ---- authentication -----------------------------------------------------------------------

func (c *Connection) initiatorHandler() (security.AuthHandler, error) {
	if c.authHandler != nil {
		return c.authHandler, nil
	}
	provider := c.authProvider
	if provider == nil && c.warehouse != nil {
		provider = c.warehouse.AuthenticationProvider(c.authProtocol)
	}
	if provider == nil {
		return nil, core.ManagementError(core.AccessDenied, "Authentication provider not found.")
	}
	c.mu.Lock()
	identity := c.localIdentity
	c.mu.Unlock()
	handler := provider.CreateHandler(security.AuthContext{
		Direction: security.Initiator, Mode: c.authMode, Domain: c.domain, HostName: c.hostName,
		InitiatorIdentity: identity, ResponderIdentity: c.responderIdentity,
	})
	if handler == nil {
		return nil, core.ManagementError(core.NotSupported, "Authentication handler not found.")
	}
	c.authProvider = provider
	c.authHandler = handler
	return handler, nil
}

func (c *Connection) requireHandler() (security.AuthHandler, error) {
	if c.authHandler == nil {
		return nil, core.ManagementError(core.AccessDenied, "Authentication handler is not initialized.")
	}
	return c.authHandler, nil
}

func (c *Connection) handleAuthPacket(p *packet.AuthPacket) {
	var err error
	switch p.Command {
	case packet.AuthInitialize:
		err = c.handleAuthInitialize(p)
	case packet.AuthAcknowledge:
		err = c.handleAuthAcknowledge(p)
	case packet.AuthAction:
		err = c.handleAuthAction(p)
	case packet.AuthEvent:
		c.handleAuthEvent(p)
	}
	if err != nil {
		c.failAuthentication(err, false)
	}
}

func (c *Connection) handleAuthInitialize(p *packet.AuthPacket) error {
	if c.direction != dirResponder {
		return core.ManagementError(core.AccessDenied, "Unexpected Initialize packet.")
	}
	headers, remoteData, err := c.parseAuthHeaders(p)
	if err != nil {
		return err
	}
	c.setRemoteHeaders(headers)
	local := c.headersWithLocal()
	if !c.negotiateEncryption(p, local) {
		return nil
	}

	if p.AuthMode == packet.AuthNone {
		if c.cfg.DenyAnonymous {
			_ = c.sendAuthData(packet.ErrorTerminate, "Unauthorized access not allowed.")
			c.failAuthentication(errors.New("Unauthorized access not allowed."), true)
			return nil
		}
		if err := c.sendAuthHeaders(packet.SessionEstablished, local); err != nil {
			return err
		}
		c.authMode = packet.AuthNone
		c.completeAuthentication(nil)
		return nil
	}

	protocol, ok := headers[packet.HeaderAuthenticationProtocol].(string)
	if !ok {
		return c.refuseAuthentication(local, "Authentication protocol is missing.")
	}
	var provider security.AuthProvider
	if c.warehouse != nil {
		provider = c.warehouse.AuthenticationProvider(protocol)
	}
	if provider == nil && c.authProvider != nil && c.authProvider.Name() == protocol {
		provider = c.authProvider
	}
	if provider == nil {
		return c.refuseAuthentication(local, "Authentication provider not found.")
	}
	c.authMode = p.AuthMode
	c.authProtocol = protocol
	c.authProvider = provider
	domain, _ := headers[packet.HeaderDomain].(string)
	if domain == "" {
		domain = c.domain
	}
	handler := provider.CreateHandler(security.AuthContext{
		Direction: security.Responder, Mode: c.authMode, Domain: domain, HostName: c.hostName,
		Materials: []security.Material{{Type: security.MaterialData, Value: remoteData}},
	})
	if handler == nil {
		return c.refuseAuthentication(local, "Authentication handler not found.")
	}
	c.authHandler = handler
	result := handler.Process(remoteData)
	local[packet.HeaderAuthenticationData] = result.AuthenticationData
	switch result.Ruling {
	case security.AuthFailed:
		if err := c.sendAuthHeaders(packet.Denied, local); err != nil {
			return err
		}
		c.failAuthentication(errors.New("Authentication failed."), true)
	case security.AuthInProgress:
		return c.sendAuthHeaders(packet.ProceedToHandshake, local)
	default:
		if err := c.sendAuthHeaders(packet.SessionEstablished, local); err != nil {
			return err
		}
		c.completeAuthentication(&result)
	}
	return nil
}

func (c *Connection) refuseAuthentication(local map[uint8]any, message string) error {
	_ = c.sendAuthHeaders(packet.NotSupported, local)
	c.failAuthentication(errors.New(message), true)
	return nil
}

func (c *Connection) handleAuthAcknowledge(p *packet.AuthPacket) error {
	if c.authMode == packet.AuthNone {
		if p.Method == packet.SessionEstablished {
			headers, _, err := c.parseAuthHeaders(p)
			if err != nil {
				return err
			}
			c.setRemoteHeaders(headers)
			if !c.acceptEncryption() {
				return nil
			}
			c.completeAuthentication(nil)
		} else {
			c.failAuthentication(errors.New(c.readAuthErrorMessage(p)), true)
		}
		return nil
	}
	switch p.Method {
	case packet.Denied, packet.NotSupported:
		c.failAuthentication(errors.New(c.readAuthErrorMessage(p)), true)
		return nil
	case packet.ProceedToHandshake, packet.ProceedToFinalHandshake, packet.SessionEstablished:
	default:
		return nil
	}
	headers, remoteData, err := c.parseAuthHeaders(p)
	if err != nil {
		return err
	}
	c.setRemoteHeaders(headers)
	if !c.acceptEncryption() {
		return nil
	}
	handler, err := c.requireHandler()
	if err != nil {
		return err
	}
	result := handler.Process(remoteData)
	switch result.Ruling {
	case security.AuthFailed:
		c.failAuthentication(errors.New("Authentication failed."), false)
	case security.AuthInProgress:
		if p.Method == packet.ProceedToHandshake {
			return c.sendAuthData(packet.Handshake, result.AuthenticationData)
		}
		c.failAuthentication(errors.New("Bad authentication protocol sequence."), false)
	default:
		c.storeAuthenticationResult(&result)
		if p.Method == packet.SessionEstablished {
			c.completeAuthentication(&result)
		} else {
			return c.sendAuthData(packet.FinalHandshake, result.AuthenticationData)
		}
	}
	return nil
}

func (c *Connection) handleAuthAction(p *packet.AuthPacket) error {
	if p.Method != packet.Handshake && p.Method != packet.FinalHandshake {
		return nil
	}
	handler, err := c.requireHandler()
	if err != nil {
		return err
	}
	remoteData, err := c.Decode(p.Tdu)
	if err != nil {
		return err
	}
	result := handler.Process(remoteData)
	switch result.Ruling {
	case security.AuthFailed:
		c.failAuthentication(errors.New("Authentication failed."), false)
	case security.AuthInProgress:
		return c.sendAuthData(packet.Handshake, result.AuthenticationData)
	default:
		c.storeAuthenticationResult(&result)
		if result.AuthenticationData != nil {
			if err := c.sendAuthData(packet.FinalHandshake, result.AuthenticationData); err != nil {
				return err
			}
		}
		if p.Method == packet.FinalHandshake || result.AuthenticationData == nil {
			message, _ := packet.ComposeMethod(packet.Established, nil)
			if err := c.Send(message); err != nil {
				return err
			}
			c.completeAuthentication(&result)
		}
	}
	return nil
}

func (c *Connection) handleAuthEvent(p *packet.AuthPacket) {
	switch p.Method {
	case packet.Established:
		if c.sessionEstablished {
			c.completeAuthentication(nil)
		} else {
			c.failAuthentication(errors.New("Authentication error."), false)
		}
	case packet.ErrorTerminate, packet.ErrorMustEncrypt, packet.ErrorRetry:
		c.failAuthentication(errors.New(c.readAuthErrorMessage(p)), true)
	}
}

func (c *Connection) storeAuthenticationResult(r *security.AuthResult) {
	c.sessionEstablished = true
	c.mu.Lock()
	c.localIdentity = r.LocalIdentity
	c.remoteIdentity = r.RemoteIdentity
	c.sessionKey = r.SessionKey
	c.mu.Unlock()
}

func (c *Connection) completeAuthentication(r *security.AuthResult) {
	if r != nil {
		c.storeAuthenticationResult(r)
	}
	c.sessionEstablished = true
	if c.encMode != packet.EncryptNone {
		// Everything up to here was the last plaintext; from now on records are protected.
		if err := c.startEncryption(); err != nil {
			c.failAuthentication(err, false)
			return
		}
	}
	c.cancelDeadline()
	c.authenticated.Store(true)
	c.succeedReady()
	if obs, ok := c.authProvider.(security.SessionObserver); ok {
		session := c.Session()
		go func() {
			defer recoverLog("authentication provider login hook")
			obs.Login(session)
		}()
	}
}

func (c *Connection) failAuthentication(err error, suppressSend bool) {
	c.cancelDeadline()
	e := core.FromError(err)
	var ce *core.Error
	if !errors.As(err, &ce) {
		e = core.ManagementError(core.AccessDenied, "%s", err.Error())
	}
	c.failReady(e)
	if !suppressSend {
		if sendErr := c.sendAuthData(packet.ErrorTerminate, e.Message); sendErr != nil {
			log.Printf("esiur: could not report an authentication failure: %v", sendErr)
		}
	}
	if s := c.sock(); s != nil {
		s.Close()
	}
}

func (c *Connection) restartDeadline() {
	c.cancelDeadline()
	if c.authTimeout <= 0 {
		return
	}
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	c.deadline = time.AfterFunc(c.authTimeout, func() {
		c.inMu.Lock()
		defer c.inMu.Unlock()
		if c.authenticated.Load() {
			return
		}
		c.failAuthentication(core.ManagementError(core.Timeout, "Authentication did not complete before the configured deadline."), true)
	})
}

func (c *Connection) cancelDeadline() {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	if c.deadline != nil {
		c.deadline.Stop()
		c.deadline = nil
	}
}
