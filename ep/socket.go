// Package ep implements the Esiur EP protocol: connections (client and server side), remote
// resource proxies, serving a warehouse, and the TCP and WebSocket transports.
package ep

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"github.com/coder/websocket"
)

// Subprotocol is the WebSocket subprotocol every EP peer must negotiate (esiur-dotnet requires
// it too).
const Subprotocol = "EP"

// Receiver receives the events of a socket. Calls are made from one goroutine at a time.
type Receiver interface {
	// NetworkReceive is called when bytes arrive. They are a slice of the stream: packets may
	// span several calls. The slice is not reused.
	NetworkReceive(s Socket, data []byte)
	// NetworkClose is called once when the socket closes, from either side.
	NetworkClose(s Socket)
}

// Socket is a transport. Send never blocks: bytes are queued and written in order.
type Socket interface {
	// Start begins delivering received bytes to r.
	Start(r Receiver)
	Send(data []byte)
	// Close flushes what is queued and closes the socket; idempotent.
	Close()
	Established() bool
	RemoteAddr() string
}

// transport is what a streamSocket reads from and writes to.
type transport interface {
	read() ([]byte, error)
	write(b []byte) error
	close() error
	remoteAddr() string
}

// streamSocket queues outbound bytes for a writer goroutine and delivers inbound bytes from a
// reader goroutine.
type streamSocket struct {
	t         transport
	mu        sync.Mutex
	cond      *sync.Cond
	queue     [][]byte
	closing   bool
	closed    bool
	started   bool
	notified  bool
	receiver  Receiver
	closeOnce sync.Once
}

func newStreamSocket(t transport) *streamSocket {
	s := &streamSocket{t: t}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *streamSocket) RemoteAddr() string { return s.t.remoteAddr() }

func (s *streamSocket) Established() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closing && !s.closed
}

func (s *streamSocket) Start(r Receiver) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.receiver = r
	s.mu.Unlock()
	go s.readLoop()
	go s.writeLoop()
}

func (s *streamSocket) Send(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.closed {
		return
	}
	s.queue = append(s.queue, data)
	s.cond.Signal()
}

func (s *streamSocket) Close() {
	s.mu.Lock()
	if s.closing || s.closed {
		s.mu.Unlock()
		return
	}
	s.closing = true
	started := s.started
	s.cond.Signal()
	s.mu.Unlock()
	if !started {
		s.finish()
	}
}

func (s *streamSocket) readLoop() {
	defer s.finish()
	for {
		data, err := s.t.read()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.mu.Lock()
				quiet := s.closing
				s.mu.Unlock()
				if !quiet {
					log.Printf("esiur: connection dropped: %v", err)
				}
			}
			return
		}
		if len(data) > 0 {
			s.receiver.NetworkReceive(s, data)
		}
	}
}

func (s *streamSocket) writeLoop() {
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && !s.closing && !s.closed {
			s.cond.Wait()
		}
		if len(s.queue) == 0 {
			s.mu.Unlock()
			s.finish() // closing with nothing left to send
			return
		}
		batch := s.queue
		s.queue = nil
		s.mu.Unlock()
		for _, b := range batch {
			if err := s.t.write(b); err != nil {
				s.finish()
				return
			}
		}
	}
}

// finish closes the transport and tells the receiver, once.
func (s *streamSocket) finish() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.queue = nil
		r := s.receiver
		s.cond.Broadcast()
		s.mu.Unlock()
		_ = s.t.close()
		if r != nil {
			go r.NetworkClose(s)
		}
	})
}

// ---- TCP ----------------------------------------------------------------------------------

type tcpTransport struct {
	c   net.Conn
	buf []byte
}

func (t *tcpTransport) read() ([]byte, error) {
	n, err := t.c.Read(t.buf)
	if n > 0 {
		return append([]byte(nil), t.buf[:n]...), nil
	}
	return nil, err
}
func (t *tcpTransport) write(b []byte) error { _, err := t.c.Write(b); return err }
func (t *tcpTransport) close() error         { return t.c.Close() }
func (t *tcpTransport) remoteAddr() string   { return t.c.RemoteAddr().String() }

// NewTCPSocket wraps an established TCP (or any stream) connection.
func NewTCPSocket(c net.Conn) Socket {
	return newStreamSocket(&tcpTransport{c: c, buf: make([]byte, 64*1024)})
}

// DialTCP connects to address ("host:port").
func DialTCP(ctx context.Context, address string) (Socket, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return NewTCPSocket(c), nil
}

// ---- WebSocket ----------------------------------------------------------------------------

type wsTransport struct {
	c      *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	remote string
}

func (t *wsTransport) read() ([]byte, error) {
	_, data, err := t.c.Read(t.ctx)
	if err != nil {
		status := websocket.CloseStatus(err)
		if status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway || status == websocket.StatusNoStatusRcvd || t.ctx.Err() != nil {
			return nil, io.EOF
		}
		return nil, err
	}
	return data, nil
}

func (t *wsTransport) write(b []byte) error { return t.c.Write(t.ctx, websocket.MessageBinary, b) }

func (t *wsTransport) close() error {
	err := t.c.Close(websocket.StatusNormalClosure, "")
	t.cancel()
	return err
}

func (t *wsTransport) remoteAddr() string { return t.remote }

// NewWebSocket wraps an established WebSocket; each binary message carries part of the byte
// stream. maximumMessageSize (0 for no limit) bounds a received message.
func NewWebSocket(c *websocket.Conn, remote string, maximumMessageSize int) Socket {
	if maximumMessageSize > 0 {
		c.SetReadLimit(int64(maximumMessageSize))
	} else {
		c.SetReadLimit(-1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return newStreamSocket(&wsTransport{c: c, ctx: ctx, cancel: cancel, remote: remote})
}

// DialWebSocket connects to a ws:// or wss:// URL, negotiating the EP subprotocol.
func DialWebSocket(ctx context.Context, url string, maximumMessageSize int) (Socket, error) {
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{Subprotocol}})
	if err != nil {
		return nil, err
	}
	if c.Subprotocol() != Subprotocol {
		c.Close(websocket.StatusProtocolError, "EP subprotocol required")
		return nil, errors.New("esiur: the server did not negotiate the required 'EP' WebSocket subprotocol")
	}
	return NewWebSocket(c, url, maximumMessageSize), nil
}
