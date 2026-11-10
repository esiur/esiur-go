// Command server hosts a Greeter resource at sys/greeter over WebSocket (ws://127.0.0.1:51018)
// and raw TCP (tcp://127.0.0.1:51019); -ws and -tcp change the addresses.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/esiur/esiur-go/ep"
	"github.com/esiur/esiur-go/resource"
	"github.com/esiur/esiur-go/security"
)

// Greeter is a resource with every kind of member.
type Greeter struct {
	resource.Base
	Visits resource.Property[int32]  // a property peers watch
	Label  resource.Property[string] `esiur:"label,readonly"` // read-only for peers
	Ping   resource.Event[string]    // peers subscribe to it
	Tick   resource.Event[string]    `esiur:",auto" arg:"message"` // pushed to every peer
}

// Greet is exported as "greet".
func (g *Greeter) Greet(name string) string {
	g.Visits.Set(g.Visits.Get() + 1)
	g.Ping.Emit("greeted " + name)
	return "Hi " + name
}

func main() {
	wsAddr := flag.String("ws", "127.0.0.1:51018", "WebSocket listen address")
	tcpAddr := flag.String("tcp", "127.0.0.1:51019", "TCP listen address")
	flag.Parse()
	ctx := context.Background()
	w := resource.NewWarehouse(nil)
	w.RegisterPermissions(security.AllowAll{}) // without a manager, peers cannot write
	if err := w.Put(ctx, "sys", resource.NewMemoryStore()); err != nil {
		log.Fatal(err)
	}
	g := &Greeter{}
	g.Label.Init("hello")
	if err := w.Put(ctx, "sys/greeter", g); err != nil {
		log.Fatal(err)
	}
	if err := w.Open(ctx); err != nil {
		log.Fatal(err)
	}

	server := ep.NewServer(w, ep.ServerConfig{})
	if _, err := server.ListenWebSocket(*wsAddr); err != nil {
		log.Fatal(err)
	}
	if _, err := server.ListenTCP(*tcpAddr); err != nil {
		log.Fatal(err)
	}
	log.Printf("serving sys/greeter on ws://%s and tcp://%s", *wsAddr, *tcpAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	server.Close()
}
