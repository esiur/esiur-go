package ep

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/esiur/esiur-go/core"
	"github.com/esiur/esiur-go/data"
	"github.com/esiur/esiur-go/packet"
	"github.com/esiur/esiur-go/resource"
	"github.com/esiur/esiur-go/security"
)

type hostedNode struct {
	warehouse      *resource.Warehouse
	server         *Server
	greeter, other *Greeter
	ws, tcp        string
}

func host(t *testing.T, cfg ServerConfig) *hostedNode {
	t.Helper()
	ctx := context.Background()
	w := resource.NewWarehouse(nil)
	w.RegisterPermissions(security.AllowAll{})
	must(t, w.Put(ctx, "sys", resource.NewMemoryStore()))
	n := &hostedNode{warehouse: w, greeter: newGreeter(), other: newGreeter()}
	must(t, w.Put(ctx, "sys/greeter", n.greeter))
	must(t, w.Put(ctx, "sys/other", n.other))
	must(t, w.Open(ctx))
	n.greeter.Partner.Set(n.other)
	n.other.Partner.Set(n.greeter)
	n.server = NewServer(w, cfg)
	ws, err := n.server.ListenWebSocket("127.0.0.1:0")
	must(t, err)
	tcp, err := n.server.ListenTCP("127.0.0.1:0")
	must(t, err)
	n.ws, n.tcp = "ws://"+ws.String(), "tcp://"+tcp.String()
	t.Cleanup(func() { n.server.Close() })
	return n
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func timeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("the condition never became true")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type recorder struct {
	mu     sync.Mutex
	values []any
}

func (r *recorder) add(v any) { r.mu.Lock(); r.values = append(r.values, v); r.mu.Unlock() }
func (r *recorder) get() []any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]any(nil), r.values...)
}

func names[M any](members []*M, name func(*M) string) []string {
	out := []string{}
	for _, m := range members {
		out = append(out, name(m))
	}
	sort.Strings(out)
	return out
}

func TestGoClientAndGoServer(t *testing.T) {
	node := host(t, ServerConfig{})
	for _, url := range []string{node.ws, node.tcp} {
		t.Run(url[:3], func(t *testing.T) {
			ctx := timeout(t)
			c, err := Connect(ctx, url, Config{})
			must(t, err)
			defer c.Close()

			greeter, err := c.Get(ctx, "sys/greeter")
			must(t, err)
			td := greeter.TypeDef()
			if td.Name() != "Greeter" {
				t.Fatalf("type %s", td.Name())
			}
			props := names(td.Properties, func(p *data.PropertyDefInfo) string { return p.Name })
			if !reflect.DeepEqual(props, []string{"label", "partner", "serial", "visits"}) {
				t.Errorf("properties %v", props)
			}
			funcs := names(td.Functions, func(p *data.FunctionDefInfo) string { return p.Name })
			if !reflect.DeepEqual(funcs, []string{"add", "echo", "fail", "fire_ping", "fire_tick", "greet", "range", "slow"}) {
				t.Errorf("functions %v", funcs)
			}
			if greeter.Value("label") != "hello" || greeter.Value("serial") != "S-1" {
				t.Errorf("values %v %v", greeter.Value("label"), greeter.Value("serial"))
			}
			again, err := c.Get(ctx, "sys/greeter")
			must(t, err)
			if again != greeter {
				t.Error("attaching twice must give the same proxy")
			}

			// The partner property refers to another resource, which refers back: a cycle.
			other, ok := greeter.Value("partner").(*RemoteResource)
			if !ok || other.Link() != "sys/other" {
				t.Fatalf("partner %#v", greeter.Value("partner"))
			}
			if other.Value("partner") != greeter {
				t.Error("a cycle must resolve to the same proxies")
			}

			// Calls.
			if v, err := greeter.Invoke(ctx, "greet", "Go"); err != nil || v != "Hi Go" {
				t.Errorf("greet %v %v", v, err)
			}
			if v, err := greeter.Invoke(ctx, "add", 2, 40); err != nil || fmt.Sprint(v) != "42" {
				t.Errorf("add %v %v", v, err)
			}
			if v, err := greeter.Invoke(ctx, "range", 4); err != nil || !reflect.DeepEqual(v, []int32{0, 1, 2, 3}) {
				t.Errorf("range %#v %v", v, err)
			}
			if v, err := greeter.Invoke(ctx, "slow", "quiet"); err != nil || v != "QUIET" {
				t.Errorf("slow %v %v", v, err)
			}
			if v, err := greeter.Invoke(ctx, "echo", other); err != nil || v != other {
				t.Errorf("echo %v %v", v, err)
			}
			_, err = greeter.Invoke(ctx, "fail")
			var ce *core.Error
			if !errors.As(err, &ce) || ce.Type != core.Exception || ce.Message != "boom" {
				t.Errorf("fail %v", err)
			}
			if _, err = greeter.Invoke(ctx, "add", 1); err == nil {
				t.Error("a call with a missing argument must fail")
			}

			// Property changes on the server are pushed to the cached value.
			changes := &recorder{}
			remove, err := greeter.OnProperty("visits", changes.add)
			must(t, err)
			before := node.greeter.Visits.Get()
			node.greeter.Visits.Set(before + 1)
			node.greeter.Visits.Set(before + 2)
			eventually(t, func() bool { return len(changes.get()) == 2 })
			if fmt.Sprint(changes.get()) != fmt.Sprint([]any{before + 1, before + 2}) {
				t.Errorf("changes %v", changes.get())
			}
			remove()

			// Writes.
			must(t, greeter.Set(ctx, "label", "written from go"))
			if node.greeter.Label.Get() != "written from go" {
				t.Errorf("label on the server %q", node.greeter.Label.Get())
			}
			err = greeter.Set(ctx, "serial", "x")
			if !errors.As(err, &ce) || ce.Code != core.ReadOnlyProperty {
				t.Errorf("read-only write %v", err)
			}
			node.greeter.Label.Set("hello")

			// Events need a subscription; auto-delivered ones do not.
			pings, ticks := &recorder{}, &recorder{}
			unsubscribe, err := greeter.OnEvent(ctx, "ping", pings.add)
			must(t, err)
			_, err = greeter.OnEvent(ctx, "tick", ticks.add)
			must(t, err)
			_, err = greeter.Invoke(ctx, "fire_ping", "one")
			must(t, err)
			node.greeter.Tick.Emit("tock")
			eventually(t, func() bool { return len(pings.get()) == 1 && len(ticks.get()) == 1 })
			must(t, unsubscribe(ctx))
			_, err = greeter.Invoke(ctx, "fire_ping", "two")
			must(t, err)
			_, err = greeter.Invoke(ctx, "fire_tick", "three")
			must(t, err)
			eventually(t, func() bool { return len(ticks.get()) == 2 })
			if fmt.Sprint(pings.get()) != "[one]" || fmt.Sprint(ticks.get()) != "[tock three]" {
				t.Errorf("pings %v ticks %v", pings.get(), ticks.get())
			}

			// Unknown resources are errors.
			_, err = c.Get(ctx, "sys/missing")
			if !errors.As(err, &ce) || ce.Code != core.ResourceNotFound {
				t.Errorf("missing %v", err)
			}

			// A detached resource stops receiving changes.
			must(t, greeter.Detach(ctx))
			v := greeter.Value("visits")
			node.greeter.Visits.Set(node.greeter.Visits.Get() + 10)
			time.Sleep(50 * time.Millisecond)
			if greeter.Value("visits") != v {
				t.Error("a detached proxy must not change")
			}

			c.Close()
			<-c.Done()
			_, err = other.Invoke(ctx, "add", 1, 1)
			if !errors.As(err, &ce) || ce.Code != core.HostNotReachable {
				t.Errorf("call after close %v", err)
			}
		})
	}
}

func TestAuthenticationAndEncryption(t *testing.T) {
	serverAuth, err := security.NewStaticPasswordProvider(
		map[string]string{"alice": "wonderland"}, map[string]string{"server": "srv-secret"}, "server")
	must(t, err)
	node := host(t, ServerConfig{DenyAnonymous: true, AuthenticationProvider: serverAuth,
		EncryptionProviders: []security.EncryptionProvider{security.AesGcm{}}})
	clientAuth, err := security.NewStaticPasswordProvider(
		map[string]string{"server": "srv-secret"}, map[string]string{"alice": "wonderland"}, "alice")
	must(t, err)

	cases := []struct {
		mode               packet.AuthenticationMode
		local, remote      string
		identity, expected string
	}{
		{packet.AuthInitializerIdentity, "alice", "", "alice", ""},
		{packet.AuthResponderIdentity, "", "server", "", "server"},
		{packet.AuthDualIdentity, "alice", "server", "alice", "server"},
	}
	for _, tc := range cases {
		for _, enc := range []packet.EncryptionMode{packet.EncryptNone, packet.EncryptWithSessionKey} {
			t.Run(fmt.Sprintf("mode%d-enc%d", tc.mode, enc), func(t *testing.T) {
				ctx := timeout(t)
				c, err := Connect(ctx, node.ws, Config{
					AuthenticationMode: tc.mode, EncryptionMode: enc,
					AuthenticationProvider: clientAuth, Identity: tc.identity,
				})
				must(t, err)
				defer c.Close()
				if c.LocalIdentity() != tc.local || c.RemoteIdentity() != tc.remote {
					t.Errorf("identities %q %q", c.LocalIdentity(), c.RemoteIdentity())
				}
				if len(c.SessionKey()) != 64 || c.IsEncrypted() != (enc != packet.EncryptNone) {
					t.Errorf("key %d encrypted %v", len(c.SessionKey()), c.IsEncrypted())
				}
				g, err := c.Get(ctx, "sys/greeter")
				must(t, err)
				if v, err := g.Invoke(ctx, "greet", "secure"); err != nil || v != "Hi secure" {
					t.Errorf("greet %v %v", v, err)
				}
				eventually(t, func() bool {
					for _, sc := range node.server.Connections() {
						if sc.RemoteIdentity() == tc.local && sc.IsEncrypted() == (enc != packet.EncryptNone) && sc.IsAuthenticated() {
							return true
						}
					}
					return false
				})
			})
		}
	}

	t.Run("anonymous refused", func(t *testing.T) {
		_, err := Connect(timeout(t), node.ws, Config{})
		if err == nil {
			t.Fatal("an anonymous peer must be refused")
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		bad, _ := security.NewStaticPasswordProvider(nil, map[string]string{"alice": "nope"}, "alice")
		_, err := Connect(timeout(t), node.tcp, Config{AuthenticationMode: packet.AuthInitializerIdentity, AuthenticationProvider: bad})
		var ce *core.Error
		if !errors.As(err, &ce) {
			t.Fatalf("a wrong password must fail, got %v", err)
		}
	})
}
