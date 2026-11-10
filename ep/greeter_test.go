package ep

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/esiur/esiur-go/resource"
)

// Greeter has the same surface as the esiur-ts test server's Greeter (and esiur-python's), so a
// client written for either side reads the same.
type Greeter struct {
	resource.Base
	Visits  resource.Property[int32]
	Label   resource.Property[string]
	Partner resource.Property[resource.Resource]
	Serial  resource.Property[string] `esiur:"serial,readonly"`
	Ping    resource.Event[string]
	Tick    resource.Event[string] `esiur:",auto"`
}

func newGreeter() *Greeter {
	g := &Greeter{}
	g.Label.Init("hello")
	g.Serial.Init("S-1")
	return g
}

func (*Greeter) FunctionNames() map[string]string {
	return map[string]string{"FirePing": "fire_ping", "FireTick": "fire_tick"}
}

func (g *Greeter) Greet(name string) string {
	g.Visits.Set(g.Visits.Get() + 1)
	return "Hi " + name
}

func (g *Greeter) FirePing(message string) { g.Ping.Emit(message) }
func (g *Greeter) FireTick(message string) { g.Tick.Emit(message) }

func (g *Greeter) Range(count int32) []int32 {
	out := make([]int32, count)
	for i := range out {
		out[i] = int32(i)
	}
	return out
}

func (g *Greeter) Echo(r resource.Resource) resource.Resource { return r }

func (g *Greeter) Add(a, b int32) int32 { return a + b }

func (g *Greeter) Fail() error { return errors.New("boom") }

func (g *Greeter) Slow(ctx context.Context, text string) (string, error) {
	select {
	case <-time.After(10 * time.Millisecond):
		return strings.ToUpper(text), nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
