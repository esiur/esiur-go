// Command client attaches to sys/greeter on an EP server (by default the one examples/server
// runs) and uses every kind of member.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/esiur/esiur-go/ep"
)

func main() {
	url := "ws://127.0.0.1:51018"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := ep.Connect(ctx, url, ep.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	greeter, err := conn.Get(ctx, "sys/greeter")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("visits:", greeter.Value("visits")) // a cached property value

	greeter.OnProperty("visits", func(v any) { fmt.Println("visits changed to", v) })
	stop, err := greeter.OnEvent(ctx, "ping", func(v any) { fmt.Println("ping:", v) })
	if err != nil {
		log.Fatal(err)
	}

	reply, err := greeter.Invoke(ctx, "greet", "Ahmed") // a remote call
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(reply)

	time.Sleep(200 * time.Millisecond) // let the notifications arrive
	stop(ctx)
}
