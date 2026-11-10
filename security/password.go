package security

import (
	"crypto/rand"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/esiur/esiur-go/packet"
)

// PasswordProtocol is the name of the password-sha3-v1 authentication protocol.
const PasswordProtocol = "password-sha3-v1"

const (
	nonceLength = 20
	saltLength  = 32
)

func sha3_256(parts ...[]byte) []byte {
	h := sha3.New256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func sha3_512(parts ...[]byte) []byte {
	h := sha3.New512()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// PasswordHash is a stored, salted password hash: Hash = SHA3-256(password + Salt).
type PasswordHash struct {
	Hash []byte
	Salt []byte
}

// CreateCredential derives a storable, salted hash from a password (a fresh random salt each
// time).
func CreateCredential(password []byte) (PasswordHash, error) {
	if len(password) == 0 {
		return PasswordHash{}, errors.New("esiur: a password cannot be empty")
	}
	salt := randomBytes(saltLength)
	return PasswordHash{Hash: sha3_256(password, salt), Salt: salt}, nil
}

// PasswordStore is what the password protocol asks of the node, for the roles it plays:
// hosting accounts (a peer logs in to this node) and proving identities (this node logs in to a
// peer, or proves the responder's own identity).
type PasswordStore interface {
	// HostedAccountCredential is the stored hash and salt of the account this node hosts; an
	// empty PasswordHash if there is no such account.
	HostedAccountCredential(identity, domain string) PasswordHash
	// SelfIdentityAndCredential is the identity and raw password this node proves when none
	// was named ("" when it has none).
	SelfIdentityAndCredential(domain, hostName string) (identity string, password []byte)
	// SelfCredential is the raw password with which this node proves identity (nil if unknown).
	SelfCredential(identity, domain, hostName string) []byte
}

// PasswordProvider is the AuthProvider of the password-sha3-v1 protocol: a challenge-response
// exchange over SHA3 where each side contributes a 20-byte nonce, the account's salted password
// hash never travels, and both end up with the same 64-byte session key.
type PasswordProvider struct {
	Store PasswordStore
	// OnLogin and OnLogout, when set, hear about sessions.
	OnLogin, OnLogout func(*Session)
}

func (p *PasswordProvider) Name() string { return PasswordProtocol }

func (p *PasswordProvider) CreateHandler(ctx AuthContext) AuthHandler {
	return &PasswordHandler{
		store: p.Store, mode: ctx.Mode, direction: ctx.Direction,
		initiatorIdentity: ctx.InitiatorIdentity, responderIdentity: ctx.ResponderIdentity,
		hostName: ctx.HostName, domain: ctx.Domain, localNonce: randomBytes(nonceLength),
	}
}

func (p *PasswordProvider) Login(s *Session) {
	if p.OnLogin != nil {
		p.OnLogin(s)
	}
}

func (p *PasswordProvider) Logout(s *Session) {
	if p.OnLogout != nil {
		p.OnLogout(s)
	}
}

// StaticPasswords is a PasswordStore backed by maps. Accounts are hosted (only salted hashes are
// kept); Credentials are the identities this node can prove, Identity the one used when none
// was asked for.
type StaticPasswords struct {
	hosted      map[string]PasswordHash
	credentials map[string][]byte
	identity    string
}

// NewStaticPasswords builds a store; accounts maps identity to password for the accounts this
// node hosts, credentials identity to password for the identities it can prove.
func NewStaticPasswords(accounts, credentials map[string]string, identity string) (*StaticPasswords, error) {
	s := &StaticPasswords{hosted: map[string]PasswordHash{}, credentials: map[string][]byte{}, identity: identity}
	for name, pw := range accounts {
		h, err := CreateCredential([]byte(pw))
		if err != nil {
			return nil, err
		}
		s.hosted[name] = h
	}
	for name, pw := range credentials {
		s.credentials[name] = []byte(pw)
	}
	if identity != "" {
		if _, ok := s.credentials[identity]; !ok {
			return nil, fmt.Errorf("esiur: no credential is known for the identity %q", identity)
		}
	}
	return s, nil
}

// NewStaticPasswordProvider is a PasswordProvider over NewStaticPasswords.
func NewStaticPasswordProvider(accounts, credentials map[string]string, identity string) (*PasswordProvider, error) {
	store, err := NewStaticPasswords(accounts, credentials, identity)
	if err != nil {
		return nil, err
	}
	return &PasswordProvider{Store: store}, nil
}

func (s *StaticPasswords) HostedAccountCredential(identity, _ string) PasswordHash {
	return s.hosted[identity]
}

func (s *StaticPasswords) SelfIdentityAndCredential(_, _ string) (string, []byte) {
	if s.identity == "" {
		return "", nil
	}
	return s.identity, s.credentials[s.identity]
}

func (s *StaticPasswords) SelfCredential(identity, _, _ string) []byte {
	return s.credentials[identity]
}

// PasswordHandler is one connection's side of the password exchange. A successful result names
// the identities from this side's point of view.
type PasswordHandler struct {
	store             PasswordStore
	mode              AuthenticationMode
	direction         Direction
	initiatorIdentity string
	responderIdentity string
	hostName, domain  string
	localNonce        []byte
	remoteNonce       []byte
	localSalt         []byte
	remoteSalt        []byte
	initiatorPassword []byte
	responderPassword []byte
	step              int
}

func (h *PasswordHandler) Protocol() string { return PasswordProtocol }

var failed = AuthResult{Ruling: AuthFailed}

func inProgress(data ...any) AuthResult {
	return AuthResult{Ruling: AuthInProgress, AuthenticationData: data}
}

func succeeded(data []any, local, remote string, key []byte) AuthResult {
	r := AuthResult{Ruling: AuthSucceeded, LocalIdentity: local, RemoteIdentity: remote, SessionKey: key}
	if data != nil {
		r.AuthenticationData = data
	}
	return r
}

func (h *PasswordHandler) stop() AuthResult {
	h.step = -1
	return failed
}

func (h *PasswordHandler) Process(authenticationData any) (result AuthResult) {
	defer func() {
		if recover() != nil { // whatever the peer sent, the answer is a failure
			h.step = -1
			result = failed
		}
	}()
	var remote []any
	if authenticationData != nil {
		list, ok := authenticationData.([]any)
		if !ok {
			return h.stop()
		}
		remote = list
	}
	switch {
	case h.direction == Initiator && h.mode == packet.AuthInitializerIdentity:
		return h.initiatorInitializer(remote)
	case h.direction == Initiator && h.mode == packet.AuthResponderIdentity:
		return h.initiatorResponder(remote)
	case h.direction == Initiator && h.mode == packet.AuthDualIdentity:
		return h.initiatorDual(remote)
	case h.direction == Responder && h.mode == packet.AuthInitializerIdentity:
		return h.responderInitializer(remote)
	case h.direction == Responder && h.mode == packet.AuthResponderIdentity:
		return h.responderResponder(remote)
	case h.direction == Responder && h.mode == packet.AuthDualIdentity:
		return h.responderDual(remote)
	}
	return h.stop()
}

func asBytes(v any) []byte {
	if b, ok := v.([]byte); ok {
		return b
	}
	return nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

func (h *PasswordHandler) validRemoteNonce() bool {
	return len(h.remoteNonce) == nonceLength && !equal(h.remoteNonce, h.localNonce)
}

func (h *PasswordHandler) loadInitiatorSelf() bool {
	if h.initiatorIdentity == "" {
		h.initiatorIdentity, h.initiatorPassword = h.store.SelfIdentityAndCredential(h.domain, h.hostName)
	} else {
		h.initiatorPassword = h.store.SelfCredential(h.initiatorIdentity, h.domain, h.hostName)
	}
	return h.initiatorIdentity != "" && h.initiatorPassword != nil
}

func (h *PasswordHandler) loadResponderSelf() bool {
	if h.responderIdentity == "" {
		h.responderIdentity, h.responderPassword = h.store.SelfIdentityAndCredential(h.domain, h.hostName)
	} else {
		h.responderPassword = h.store.SelfCredential(h.responderIdentity, h.domain, h.hostName)
	}
	return h.responderIdentity != "" && h.responderPassword != nil
}

func (h *PasswordHandler) initiatorInitializer(remote []any) AuthResult {
	if h.step == 0 {
		if !h.loadInitiatorSelf() {
			return failed
		}
		h.step = 1
		return inProgress(h.localNonce, h.initiatorIdentity)
	}
	if h.step != 1 || len(remote) < 3 {
		return failed
	}
	h.remoteNonce, h.remoteSalt = asBytes(remote[0]), asBytes(remote[1])
	remoteChallenge := asBytes(remote[2])
	if !h.validRemoteNonce() || len(h.remoteSalt) == 0 || len(remoteChallenge) == 0 {
		return h.stop()
	}
	hashed := sha3_256(h.initiatorPassword, h.remoteSalt)
	if !equal(remoteChallenge, sha3_256(h.remoteNonce, hashed, h.localNonce)) {
		return h.stop()
	}
	localChallenge := sha3_256(h.localNonce, hashed, h.remoteNonce)
	key := sha3_512([]byte(h.initiatorIdentity), hashed, h.localNonce, h.remoteNonce)
	h.step = -1
	return succeeded([]any{localChallenge}, h.initiatorIdentity, "", key)
}

func (h *PasswordHandler) initiatorResponder(remote []any) AuthResult {
	switch h.step {
	case 0:
		h.step = 1
		return inProgress(h.localNonce)
	case 1:
		if len(remote) < 2 {
			return failed
		}
		h.remoteNonce, h.responderIdentity = asBytes(remote[0]), asString(remote[1])
		if !h.validRemoteNonce() || h.responderIdentity == "" {
			return h.stop()
		}
		cred := h.store.HostedAccountCredential(h.responderIdentity, h.domain)
		h.localSalt, h.responderPassword = cred.Salt, cred.Hash
		if len(h.localSalt) == 0 || len(h.responderPassword) == 0 {
			return h.stop()
		}
		challenge := sha3_256(h.localNonce, h.responderPassword, h.remoteNonce)
		h.step = 2
		return inProgress(h.localSalt, challenge)
	}
	if h.step != 2 || len(remote) < 1 {
		return failed
	}
	remoteChallenge := asBytes(remote[0])
	if len(remoteChallenge) == 0 || h.remoteNonce == nil || h.responderPassword == nil {
		return h.stop()
	}
	if !equal(remoteChallenge, sha3_256(h.remoteNonce, h.responderPassword, h.localNonce)) {
		return h.stop()
	}
	key := sha3_512([]byte(h.responderIdentity), h.responderPassword, h.localNonce, h.remoteNonce)
	h.step = -1
	return succeeded(nil, h.initiatorIdentity, h.responderIdentity, key)
}

// dualResponderStep reads the responder's identity and salt, in either order (esiur-dotnet
// and esiur-ts differ in it).
func dualResponderStep(remote []any) (string, []byte) {
	if s, ok := remote[1].(string); ok {
		return s, asBytes(remote[2])
	}
	if s, ok := remote[2].(string); ok {
		return s, asBytes(remote[1])
	}
	return "", nil
}

func (h *PasswordHandler) initiatorDual(remote []any) AuthResult {
	switch h.step {
	case 0:
		if !h.loadInitiatorSelf() {
			return failed
		}
		h.step = 1
		return inProgress(h.localNonce, h.initiatorIdentity)
	case 1:
		if len(remote) < 3 {
			return failed
		}
		h.remoteNonce = asBytes(remote[0])
		identity, salt := dualResponderStep(remote)
		h.responderIdentity, h.remoteSalt = identity, salt
		if !h.validRemoteNonce() || identity == "" || len(salt) == 0 {
			return h.stop()
		}
		cred := h.store.HostedAccountCredential(identity, h.domain)
		h.localSalt, h.responderPassword = cred.Salt, cred.Hash
		if len(h.localSalt) == 0 || len(h.responderPassword) == 0 {
			return h.stop()
		}
		hashed := sha3_256(h.initiatorPassword, salt)
		challenge := sha3_256(h.localNonce, hashed, h.responderPassword, h.remoteNonce)
		h.step = 2
		return inProgress(h.localSalt, challenge)
	}
	if h.step != 2 || len(remote) < 1 {
		return failed
	}
	remoteChallenge := asBytes(remote[0])
	if len(remoteChallenge) == 0 || h.remoteNonce == nil || h.remoteSalt == nil || h.responderPassword == nil || h.initiatorPassword == nil {
		return h.stop()
	}
	hashed := sha3_256(h.initiatorPassword, h.remoteSalt)
	if !equal(remoteChallenge, sha3_256(h.remoteNonce, h.responderPassword, hashed, h.localNonce)) {
		return h.stop()
	}
	key := sha3_512([]byte(h.initiatorIdentity), []byte(h.responderIdentity), hashed, h.responderPassword, h.localNonce, h.remoteNonce)
	h.step = -1
	return succeeded(nil, h.initiatorIdentity, h.responderIdentity, key)
}

func (h *PasswordHandler) responderInitializer(remote []any) AuthResult {
	if h.step == 0 {
		if len(remote) < 2 {
			return failed
		}
		h.remoteNonce, h.initiatorIdentity = asBytes(remote[0]), asString(remote[1])
		if !h.validRemoteNonce() || h.initiatorIdentity == "" {
			return h.stop()
		}
		cred := h.store.HostedAccountCredential(h.initiatorIdentity, h.domain)
		h.localSalt, h.initiatorPassword = cred.Salt, cred.Hash
		if len(h.localSalt) == 0 || len(h.initiatorPassword) == 0 {
			return failed
		}
		challenge := sha3_256(h.localNonce, h.initiatorPassword, h.remoteNonce)
		h.step = 1
		return inProgress(h.localNonce, h.localSalt, challenge)
	}
	if h.step != 1 || len(remote) < 1 {
		return failed
	}
	remoteChallenge := asBytes(remote[0])
	if len(remoteChallenge) == 0 || h.remoteNonce == nil || h.initiatorPassword == nil {
		return h.stop()
	}
	if !equal(sha3_256(h.remoteNonce, h.initiatorPassword, h.localNonce), remoteChallenge) {
		return h.stop()
	}
	key := sha3_512([]byte(h.initiatorIdentity), h.initiatorPassword, h.remoteNonce, h.localNonce)
	h.step = -1
	return succeeded(nil, h.responderIdentity, h.initiatorIdentity, key)
}

func (h *PasswordHandler) responderResponder(remote []any) AuthResult {
	if h.step == 0 {
		if len(remote) < 1 {
			return failed
		}
		h.remoteNonce = asBytes(remote[0])
		if !h.validRemoteNonce() {
			return h.stop()
		}
		if !h.loadResponderSelf() {
			return failed
		}
		h.step = 1
		return inProgress(h.localNonce, h.responderIdentity)
	}
	if h.step != 1 || len(remote) < 2 {
		return failed
	}
	h.remoteSalt = asBytes(remote[0])
	remoteChallenge := asBytes(remote[1])
	if len(h.remoteSalt) == 0 || len(remoteChallenge) == 0 || h.remoteNonce == nil || h.responderPassword == nil {
		return h.stop()
	}
	hashed := sha3_256(h.responderPassword, h.remoteSalt)
	if !equal(sha3_256(h.remoteNonce, hashed, h.localNonce), remoteChallenge) {
		return h.stop()
	}
	localChallenge := sha3_256(h.localNonce, hashed, h.remoteNonce)
	key := sha3_512([]byte(h.responderIdentity), hashed, h.remoteNonce, h.localNonce)
	h.step = -1
	return succeeded([]any{localChallenge}, h.responderIdentity, "", key)
}

func (h *PasswordHandler) responderDual(remote []any) AuthResult {
	if h.step == 0 {
		if len(remote) < 2 {
			return failed
		}
		h.remoteNonce, h.initiatorIdentity = asBytes(remote[0]), asString(remote[1])
		if !h.validRemoteNonce() || h.initiatorIdentity == "" {
			return h.stop()
		}
		if !h.loadResponderSelf() {
			return failed
		}
		cred := h.store.HostedAccountCredential(h.initiatorIdentity, h.domain)
		h.localSalt, h.initiatorPassword = cred.Salt, cred.Hash
		if len(h.localSalt) == 0 || len(h.initiatorPassword) == 0 {
			return failed
		}
		h.step = 1
		return inProgress(h.localNonce, h.responderIdentity, h.localSalt)
	}
	if h.step != 1 || len(remote) < 2 {
		return failed
	}
	remoteSalt, remoteChallenge := asBytes(remote[0]), asBytes(remote[1])
	if len(remoteSalt) == 0 || len(remoteChallenge) == 0 || h.remoteNonce == nil || h.initiatorPassword == nil || h.responderPassword == nil {
		return h.stop()
	}
	hashed := sha3_256(h.responderPassword, remoteSalt)
	if !equal(sha3_256(h.remoteNonce, h.initiatorPassword, hashed, h.localNonce), remoteChallenge) {
		return h.stop()
	}
	localChallenge := sha3_256(h.localNonce, hashed, h.initiatorPassword, h.remoteNonce)
	key := sha3_512([]byte(h.initiatorIdentity), []byte(h.responderIdentity), h.initiatorPassword, hashed, h.remoteNonce, h.localNonce)
	h.step = -1
	return succeeded([]any{localChallenge}, h.responderIdentity, h.initiatorIdentity, key)
}
