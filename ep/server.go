package ep

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/esiur/esiur-go/resource"
	"github.com/esiur/esiur-go/security"
)

// ServerConfig configures a Server.
type ServerConfig struct {
	// DenyAnonymous refuses peers that do not authenticate.
	DenyAnonymous bool
	// AuthenticationTimeout as in Config.
	AuthenticationTimeout time.Duration
	// Parser is the receive budget; nil means DefaultParserConfig.
	Parser *ParserConfig
	// AuthenticationProvider, when set, is registered on the warehouse.
	AuthenticationProvider security.AuthProvider
	// EncryptionProviders are registered on the warehouse (when not already).
	EncryptionProviders []security.EncryptionProvider
}

// Server accepts EP connections and serves a Warehouse to them. Every accepted socket becomes a
// Connection that runs the responder handshake and then answers the peer's requests.
//
//	server := ep.NewServer(warehouse, ep.ServerConfig{})
//	ws, _ := server.ListenWebSocket("127.0.0.1:51018")
//	tcp, _ := server.ListenTCP("127.0.0.1:51019")
//	...
//	server.Close()
type Server struct {
	Warehouse *resource.Warehouse
	cfg       ServerConfig
	parser    ParserConfig

	mu          sync.Mutex
	connections map[*Connection]struct{}
	listeners   []net.Listener
	https       []*http.Server
	closed      bool
}

// NewServer creates a server for w.
func NewServer(w *resource.Warehouse, cfg ServerConfig) *Server {
	if cfg.AuthenticationProvider != nil {
		w.RegisterAuthenticationProvider(cfg.AuthenticationProvider)
	}
	for _, p := range cfg.EncryptionProviders {
		if w.EncryptionProvider(p.Name()) == nil {
			_ = w.RegisterEncryptionProvider(p)
		}
	}
	parser := DefaultParserConfig()
	if cfg.Parser != nil {
		parser = *cfg.Parser
	}
	return &Server{Warehouse: w, cfg: cfg, parser: parser, connections: map[*Connection]struct{}{}}
}

// Connections lists the live peer connections.
func (s *Server) Connections() []*Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Connection, 0, len(s.connections))
	for c := range s.connections {
		out = append(out, c)
	}
	return out
}

// Accept serves an established socket (the listeners call this for what they accept; call it
// directly to serve a transport the server does not listen on).
func (s *Server) Accept(socket Socket) *Connection {
	parser := s.parser
	c := NewConnection(Config{
		Parser: &parser, DenyAnonymous: s.cfg.DenyAnonymous,
		AuthenticationTimeout: s.cfg.AuthenticationTimeout, Warehouse: s.Warehouse,
	})
	c.StartResponderHandshake() // wait for the peer's Initialize
	s.mu.Lock()
	s.connections[c] = struct{}{}
	s.mu.Unlock()
	c.OnClose(func(c *Connection) {
		s.mu.Lock()
		delete(s.connections, c)
		s.mu.Unlock()
	})
	c.Assign(socket)
	return c
}

// ListenTCP listens for raw EP over TCP on address ("host:port"; port 0 picks a free one) and
// returns the bound address.
func (s *Server) ListenTCP(address string) (net.Addr, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, l)
	s.mu.Unlock()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.Accept(NewTCPSocket(conn))
		}
	}()
	return l.Addr(), nil
}

// ListenWebSocket listens for EP over WebSocket (subprotocol "EP") on address and returns the
// bound address.
func (s *Server) ListenWebSocket(address string) (net.Addr, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: s}
	s.mu.Lock()
	s.https = append(s.https, srv)
	s.mu.Unlock()
	go func() { _ = srv.Serve(l) }()
	return l.Addr(), nil
}

// ServeHTTP accepts a WebSocket upgrade, so a Server can be mounted on any http.ServeMux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       []string{Subprotocol},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	if ws.Subprotocol() != Subprotocol {
		ws.Close(websocket.StatusProtocolError, fmt.Sprintf("The '%s' WebSocket subprotocol is required.", Subprotocol))
		return
	}
	c := s.Accept(NewWebSocket(ws, r.RemoteAddr, s.parser.MaximumEncryptedRecordSize))
	// The upgraded connection lives as long as this handler, so hold it for the session.
	<-c.Done()
}

// Close stops listening and closes every connection.
func (s *Server) Close() error {
	s.mu.Lock()
	listeners, https := s.listeners, s.https
	s.listeners, s.https = nil, nil
	s.closed = true
	s.mu.Unlock()
	var errs []error
	for _, l := range listeners {
		if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	for _, h := range https {
		_ = h.Close()
	}
	for _, c := range s.Connections() {
		c.Close()
		<-c.Done()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, h := range https {
		_ = h.Shutdown(ctx)
	}
	return errors.Join(errs...)
}
