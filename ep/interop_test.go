package ep

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/esiur/esiur-go/core"
	"github.com/esiur/esiur-go/packet"
	"github.com/esiur/esiur-go/security"
)

// Interoperability with a real esiur-ts peer, in both directions. These tests run when Node and
// an esiur-ts checkout with its dependencies are available (ESIUR_TS_PATH, default
// ../../esiur-ts from this package); otherwise they are skipped.

func tsRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("ESIUR_TS_PATH")
	if root == "" {
		root = filepath.Join("..", "..", "esiur-ts")
	}
	root, _ = filepath.Abs(root)
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("needs Node")
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules", "esbuild")); err != nil {
		t.Skip("needs an esiur-ts checkout with its dependencies installed (ESIUR_TS_PATH)")
	}
	return root
}

type nodeProcess struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan map[string]any
}

func startNode(t *testing.T, args ...string) *nodeProcess {
	t.Helper()
	cmd := exec.Command("node", args...)
	stdin, err := cmd.StdinPipe()
	must(t, err)
	stdout, err := cmd.StdoutPipe()
	must(t, err)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	must(t, cmd.Start())
	p := &nodeProcess{cmd: cmd, stdin: stdin, lines: make(chan map[string]any, 8)}
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		for scanner.Scan() {
			var m map[string]any
			if json.Unmarshal(scanner.Bytes(), &m) == nil {
				p.lines <- m
			}
		}
		close(p.lines)
	}()
	t.Cleanup(func() {
		stdin.Close()
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
		}
		if t.Failed() && stderr.Len() > 0 {
			t.Logf("node stderr:\n%s", stderr.String())
		}
	})
	return p
}

func (p *nodeProcess) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case m, ok := <-p.lines:
		if !ok {
			t.Fatal("the node process ended without output")
		}
		return m
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for the node process")
	}
	return nil
}

type tsServer struct {
	Port      int     `json:"port"`
	GreeterID float64 `json:"greeterId"`
	OtherID   float64 `json:"otherId"`
}

func startTsServer(t *testing.T) tsServer {
	root := tsRoot(t)
	p := startNode(t, filepath.Join("..", "tools", "ts-test-server.mjs"), root)
	m := p.next(t)
	raw, _ := json.Marshal(m)
	var s tsServer
	must(t, json.Unmarshal(raw, &s))
	return s
}

func TestGoClientAgainstEsiurTsServer(t *testing.T) {
	server := startTsServer(t)
	ctx := timeout(t)
	c, err := Connect(ctx, fmt.Sprintf("ws://127.0.0.1:%d", server.Port), Config{})
	must(t, err)
	defer c.Close()

	greeter, err := c.Get(ctx, "sys/greeter")
	must(t, err)
	if greeter.InstanceID() != uint32(server.GreeterID) || greeter.TypeDef().Name() != "Greeter" {
		t.Fatalf("attached %v", greeter)
	}
	if _, ok := greeter.Value("label").(string); !ok {
		t.Errorf("label %#v", greeter.Value("label"))
	}
	if greeter.Cursor().IsEmpty() {
		t.Error("the cursor must not be empty after attaching")
	}

	other, ok := greeter.Value("partner").(*RemoteResource)
	if !ok || other.InstanceID() != uint32(server.OtherID) || other.Value("partner") != greeter {
		t.Fatalf("partner cycle: %#v", greeter.Value("partner"))
	}

	if v, err := greeter.Invoke(ctx, "greet", "Go"); err != nil || v != "Hi Go" {
		t.Errorf("greet %v %v", v, err)
	}
	if v, err := greeter.Invoke(ctx, "add", 2, 40); err != nil || fmt.Sprint(v) != "42" {
		t.Errorf("add %v %v", v, err)
	}
	if v, err := greeter.Invoke(ctx, "range", 4); err != nil || fmt.Sprint(v) != "[0 1 2 3]" {
		t.Errorf("range %#v %v", v, err)
	}
	// Not echo(other): an esiur-ts server decodes invoke arguments without resolving
	// LocalResource references, so echoing one back throws there (and ends the process).
	_, err = greeter.Invoke(ctx, "fail")
	var ce *core.Error
	if !errors.As(err, &ce) || ce.Type != core.Exception || !strings.Contains(ce.Message, "boom") {
		t.Errorf("fail %v", err)
	}

	// greet changes visits on the server: the change is pushed.
	changes := &recorder{}
	_, err = greeter.OnProperty("visits", changes.add)
	must(t, err)
	before, _ := greeter.Value("visits").(int8)
	_, err = greeter.Invoke(ctx, "greet", "again")
	must(t, err)
	eventually(t, func() bool { return len(changes.get()) == 1 })
	if fmt.Sprint(changes.get()[0]) != fmt.Sprint(int(before)+1) {
		t.Errorf("visits change %v after %v", changes.get(), before)
	}

	// Writes are visible to a second connection.
	must(t, other.Set(ctx, "label", "written from go"))
	c2, err := Connect(ctx, fmt.Sprintf("ws://127.0.0.1:%d", server.Port), Config{})
	must(t, err)
	defer c2.Close()
	seen, err := c2.Get(ctx, "sys/other")
	must(t, err)
	if seen.Value("label") != "written from go" {
		t.Errorf("label seen by another connection %v", seen.Value("label"))
	}

	// Events: ping needs a subscription, tick is auto-delivered.
	pings, ticks := &recorder{}, &recorder{}
	stop, err := greeter.OnEvent(ctx, "ping", pings.add)
	must(t, err)
	_, err = greeter.OnEvent(ctx, "tick", ticks.add)
	must(t, err)
	_, err = greeter.Invoke(ctx, "firePing", "one")
	must(t, err)
	_, err = greeter.Invoke(ctx, "fireTick", "two")
	must(t, err)
	eventually(t, func() bool { return len(pings.get()) == 1 && len(ticks.get()) == 1 })
	must(t, stop(ctx))
	_, err = greeter.Invoke(ctx, "firePing", "unheard")
	must(t, err)
	_, err = greeter.Invoke(ctx, "fireTick", "three")
	must(t, err)
	eventually(t, func() bool { return len(ticks.get()) == 2 })
	if !reflect.DeepEqual(pings.get(), []any{"one"}) || !reflect.DeepEqual(ticks.get(), []any{"two", "three"}) {
		t.Errorf("pings %v ticks %v", pings.get(), ticks.get())
	}

	_, err = c.Get(ctx, "sys/missing")
	if !errors.As(err, &ce) || ce.Code != core.ResourceNotFound {
		t.Errorf("missing %v", err)
	}
}

func TestGoAuthenticatesToEsiurTsServer(t *testing.T) {
	server := startTsServer(t)
	url := fmt.Sprintf("ws://127.0.0.1:%d", server.Port)
	auth, err := security.NewStaticPasswordProvider(
		map[string]string{"server": "srv-secret"}, map[string]string{"alice": "wonderland"}, "alice")
	must(t, err)
	big := strings.Repeat("x", 300_000)
	for _, mode := range []packet.AuthenticationMode{packet.AuthInitializerIdentity, packet.AuthResponderIdentity, packet.AuthDualIdentity} {
		for _, enc := range []packet.EncryptionMode{packet.EncryptNone, packet.EncryptWithSessionKey} {
			t.Run(fmt.Sprintf("mode%d-enc%d", mode, enc), func(t *testing.T) {
				ctx := timeout(t)
				identity := "alice"
				if mode == packet.AuthResponderIdentity {
					identity = ""
				}
				c, err := Connect(ctx, url, Config{AuthenticationMode: mode, EncryptionMode: enc, AuthenticationProvider: auth, Identity: identity})
				must(t, err)
				defer c.Close()
				wantLocal, wantRemote := "alice", "server"
				switch mode {
				case packet.AuthInitializerIdentity:
					wantRemote = ""
				case packet.AuthResponderIdentity:
					wantLocal = ""
				}
				if !c.IsAuthenticated() || c.IsEncrypted() != (enc != packet.EncryptNone) || len(c.SessionKey()) != 64 ||
					c.LocalIdentity() != wantLocal || c.RemoteIdentity() != wantRemote {
					t.Errorf("session: encrypted %v key %d local %q remote %q", c.IsEncrypted(), len(c.SessionKey()), c.LocalIdentity(), c.RemoteIdentity())
				}
				if enc != packet.EncryptNone && mode != packet.AuthInitializerIdentity {
					// In these modes the initiator sends the last plaintext message (Established)
					// and may encrypt right away, but an esiur-ts responder turns decryption on
					// only after an asynchronous cipher setup (EpConnection.completeAuthentication
					// -> prepareSessionEncryption), parsing anything that arrives meanwhile as
					// plaintext. Give it that moment; the Go side is not waiting on anything.
					time.Sleep(100 * time.Millisecond)
				}
				g, err := c.Get(ctx, "sys/greeter")
				must(t, err)
				if v, err := g.Invoke(ctx, "add", 20, 22); err != nil || fmt.Sprint(v) != "42" {
					t.Errorf("add %v %v", v, err)
				}
				heard := &recorder{}
				_, err = g.OnEvent(ctx, "ping", heard.add)
				must(t, err)
				_, err = g.Invoke(ctx, "firePing", "secured")
				must(t, err)
				eventually(t, func() bool { return len(heard.get()) == 1 })
				if v, err := g.Invoke(ctx, "greet", big); err != nil || v != "Hi "+big {
					t.Errorf("a large payload failed: %v", err)
				}
			})
		}
	}
	t.Run("wrong password", func(t *testing.T) {
		bad, _ := security.NewStaticPasswordProvider(nil, map[string]string{"alice": "not it"}, "alice")
		_, err := Connect(timeout(t), url, Config{AuthenticationMode: packet.AuthInitializerIdentity, AuthenticationProvider: bad, Identity: "alice"})
		if err == nil {
			t.Fatal("a wrong password must be refused")
		}
	})
	t.Run("server it cannot verify", func(t *testing.T) {
		wrong, _ := security.NewStaticPasswordProvider(map[string]string{"server": "some other password"}, map[string]string{"alice": "wonderland"}, "alice")
		_, err := Connect(timeout(t), url, Config{AuthenticationMode: packet.AuthDualIdentity, AuthenticationProvider: wrong, Identity: "alice"})
		if err == nil {
			t.Fatal("a server proving the wrong password must be refused")
		}
	})
}

func runTsClient(t *testing.T, port int, options map[string]any) *nodeProcess {
	root := tsRoot(t)
	opts, _ := json.Marshal(options)
	return startNode(t, filepath.Join("..", "tools", "ts-test-client.mjs"), fmt.Sprint(port), root, string(opts))
}

func portOf(url string) int {
	var port int
	fmt.Sscanf(url[strings.LastIndex(url, ":")+1:], "%d", &port)
	return port
}

func TestEsiurTsClientUsesGoServer(t *testing.T) {
	tsRoot(t)
	node := host(t, ServerConfig{})
	client := runTsClient(t, portOf(node.ws), map[string]any{})
	attached := client.next(t)
	if attached["phase"] != "attached" {
		t.Fatalf("client reported %v", attached)
	}
	check := func(key string, want any) {
		t.Helper()
		if !reflect.DeepEqual(attached[key], want) {
			t.Errorf("%s = %#v, want %#v", key, attached[key], want)
		}
	}
	check("typeName", "Greeter")
	check("properties", []any{"label", "partner", "serial", "visits"})
	check("functions", []any{"add", "echo", "fail", "fire_ping", "fire_tick", "greet", "range", "slow"})
	check("events", []any{"ping", "tick"})
	check("visits0", float64(0))
	check("label0", "hello")
	check("serial0", "S-1")
	check("greeterId", float64(resourceID(node.greeter)))
	check("partnerId", float64(resourceID(node.other)))
	check("otherId", float64(resourceID(node.other)))
	check("cycle", true)
	check("greet", "Hi TS")
	check("add", float64(42))
	check("range", []any{float64(0), float64(1), float64(2), float64(3)})
	check("slow", "QUIET")
	check("echoId", float64(resourceID(node.other)))
	check("pings", []any{"from ts"})
	check("ticks", []any{"tick from ts"})
	if !strings.Contains(fmt.Sprint(attached["fail"]), "boom") {
		t.Errorf("fail = %v", attached["fail"])
	}
	if attached["badCall"] == "no error" {
		t.Error("a call with a missing argument must fail")
	}
	if node.greeter.Label.Get() != "written by ts" {
		t.Errorf("label written by ts: %q", node.greeter.Label.Get())
	}
	check("visitsAfterGreets", float64(node.greeter.Visits.Get()))

	// Changes made on the Go side reach the TS client.
	extra := newGreeter()
	must(t, node.warehouse.Put(context.Background(), "sys/extra", extra))
	node.greeter.Visits.Set(99)
	node.greeter.Label.Set("from go")
	node.greeter.Partner.Set(extra)
	node.greeter.Ping.Emit("from go")
	node.greeter.Tick.Emit("tick from go")
	fmt.Fprintln(client.stdin, "go")
	final := client.next(t)
	if final["visits"] != float64(99) || final["label"] != "from go" || final["partnerId"] != float64(resourceID(extra)) ||
		!reflect.DeepEqual(final["pings"], []any{"from ts", "from go"}) ||
		!reflect.DeepEqual(final["ticks"], []any{"tick from ts", "tick from go"}) {
		t.Errorf("final %v", final)
	}
}

func resourceID(g *Greeter) uint32 { return g.Instance().ID }

func TestEsiurTsClientAuthenticatesToGoServer(t *testing.T) {
	tsRoot(t)
	auth, err := security.NewStaticPasswordProvider(
		map[string]string{"alice": "wonderland"}, map[string]string{"server": "srv-secret"}, "server")
	must(t, err)
	node := host(t, ServerConfig{DenyAnonymous: true, AuthenticationProvider: auth,
		EncryptionProviders: []security.EncryptionProvider{security.AesGcm{}}})
	for _, mode := range []packet.AuthenticationMode{packet.AuthInitializerIdentity, packet.AuthResponderIdentity, packet.AuthDualIdentity} {
		for _, enc := range []packet.EncryptionMode{packet.EncryptNone, packet.EncryptWithSessionKey} {
			t.Run(fmt.Sprintf("mode%d-enc%d", mode, enc), func(t *testing.T) {
				client := runTsClient(t, portOf(node.ws), map[string]any{"authenticationMode": int(mode), "encryptionMode": int(enc)})
				attached := client.next(t)
				if attached["phase"] != "attached" {
					t.Fatalf("client reported %v", attached)
				}
				if attached["encrypted"] != (enc != packet.EncryptNone) || attached["keyLength"] != float64(64) ||
					attached["greet"] != "Hi TS" || attached["echoId"] != attached["otherId"] {
					t.Errorf("attached %v", attached)
				}
				node.greeter.Label.Set("changed in go")
				fmt.Fprintln(client.stdin, "go")
				if final := client.next(t); final["label"] != "changed in go" {
					t.Errorf("final %v", final)
				}
			})
		}
	}
	t.Run("wrong password", func(t *testing.T) {
		client := runTsClient(t, portOf(node.ws), map[string]any{"authenticationMode": 1, "password": "not it"})
		if report := client.next(t); report["phase"] != "error" {
			t.Errorf("a wrong password must be refused, got %v", report)
		}
	})
}
