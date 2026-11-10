# Esiur for Go

Go implementation of Esiur v3, a distributed resource framework for real-time properties,
asynchronous function invocation and events over the Esiur EP protocol. It is a port of
[esiur-ts](https://github.com/esiur/esiur-ts) (following the layering of
[esiur-python](https://github.com/esiur/esiur-python)) and must stay wire-compatible with
[esiur-dotnet](https://github.com/esiur/esiur-dotnet).

```
go get github.com/esiur/esiur-go
```

> **Status: alpha.** The wire data layer, packets, connections over WebSocket and TCP, **remote
> resources** (attach, read properties, call functions, write properties, events), **hosting**
> (`resource.Warehouse`, `ep.Server`) and **authentication and encryption** (password login,
> AES-GCM records) exist and interoperate with esiur-ts in both directions.
>
> **Compatibility:** interoperability is tested against a real esiur-ts client and server
> (`ep/interop_test.go`, run when Node and an esiur-ts checkout are available). It has **not** yet
> been verified against esiur-dotnet.

## Port status

| Layer | Status |
| --- | --- |
| TDU framing, parser limits (`data`) | Done |
| Dynamic values, typed lists/maps/tuples, group-varint integer arrays, Tru | Done, byte-identical to esiur-ts on its 58 value vectors |
| TypeDefs: indexed structures, `TypeDefInfo` and member infos, signatures, records, enums, `TypeRegistry` | Done, byte-identical to esiur-ts on its TypeDef, signature and name64 vectors |
| EP packets (`packet`) | Done; compose and parse match esiur-ts on every header byte, every truncation and the edge cases |
| `ep.Connection`: anonymous handshake (both roles), request/reply correlation, progress/warning/chunk replies, notifications, limits exchange | Done. Not yet: reconnect, keep-alive |
| Remote resources (`ep.RemoteResource`): attach/get, TypeDef fetching, property snapshots and notifications, calls, writes, ref-counted event subscriptions, resource references (including cycles) | Done. Not yet: streaming functions, historical replay, reattach, TypeDef sync, records/enums from a peer's TypeDefs |
| Hosting (`resource`): `Base`, `Property[T]`, `Event[T]`, exported methods, `Instance`, `Warehouse`, `MemoryStore`, permissions managers | Done. Not yet: static functions, historical members, persistent stores |
| Server-side handlers: attach, detach, link lookup, TypeDef by id / by resource, invoke, set property, subscribe, unsubscribe | Done. Answered `NotImplemented`: reattach, TypeDef sync, query, create/delete/move, streams, journal |
| Transports: WebSocket (subprotocol `EP`, via `github.com/coder/websocket`) and TCP, client and server | Done. HTTP long-poll not started |
| Authentication: `password-sha3-v1` in all three modes | Done, both directions against esiur-ts |
| Encryption: `aes-gcm` (AES-256-GCM records, HKDF-SHA256 keys) | Done, both directions against esiur-ts. Not yet: address-bound mode |

## Go mapping

The Go type of a value picks its wire type, the way esiur-dotnet does:

| Go | Wire |
| --- | --- |
| `nil`, `bool` | Null, True/False |
| `int`, `int64`; `int8/16/32` | narrowest signed width up to the type's own |
| `uint`, `uint8/16/32/64` | narrowest unsigned width up to the type's own |
| `float64`, `float32` | Int8/16/32 when whole, else Float32 when exact, else Float64; NaN/Inf is one token |
| `string`, `[]byte` | String (UTF-8), RawData |
| `time.Time` | DateTime (100 ns ticks, UTC) |
| `data.UUID`, `data.Decimal`, `data.Int128`, `data.UInt128`, `data.Char16` | UUID, Decimal128, Int128, UInt128, Char16 |
| `[]any`, `data.Map` | List, Map (self-describing; `Map` keeps order) |
| `[]T`, `map[K]V` | TypedList\<T\>, TypedMap\<K,V\> (keys sorted) |
| `data.TypedList`, `data.TypedMap`, `data.TypedTuple` | typed values with explicit Trus (`data.T.I32`, `data.T.List(...)`) |
| `data.Tru`, `*data.TypeDefInfo` | TRU, TypeDef |
| registered struct / named integer | record / enum (`TypeRegistry.RegisterRecord`, `RegisterEnum`) |
| hosted resource, `*ep.RemoteResource` | resource reference |

Decoding gives each fixed-width number the Go type of its wire width (`int8`, `uint32`, …),
lists `[]any`, maps `data.Map`, typed lists a slice of the element type (`[]int32`,
`[]string`, …) and typed maps a Go map. `data.As[T](v)` and `data.Convert` turn a decoded value
into the Go type you want.

## Hosting resources

```go
type Greeter struct {
	resource.Base
	Visits resource.Property[int32]
	Label  resource.Property[string] `esiur:"label,readonly"`
	Ping   resource.Event[string]
	Tick   resource.Event[string]    `esiur:",auto"` // pushed to every attached peer
}

func (g *Greeter) Greet(name string) string { // exported as "greet"
	g.Visits.Set(g.Visits.Get() + 1)
	g.Ping.Emit("greeted " + name)
	return "Hi " + name
}

w := resource.NewWarehouse(nil)
w.RegisterPermissions(security.AllowAll{}) // without a manager, peers cannot write
w.Put(ctx, "sys", resource.NewMemoryStore())
w.Put(ctx, "sys/greeter", &Greeter{})
w.Open(ctx)
server := ep.NewServer(w, ep.ServerConfig{})
server.ListenWebSocket("127.0.0.1:51018") // or ListenTCP; Server is also an http.Handler
```

Exported `Property` and `Event` fields are the properties and events, indexed in declaration
order (embedded structs first). Exported methods are the functions, indexed in name order. A
method may take a `context.Context` first (`ep.ConnectionFrom(ctx)` is the caller) and return a
value, an error, or both. Peers address members by index, so add or remove them only together
with their clients. Names are lower camel case by default; an `esiur:"name"` tag renames a field,
and `FunctionNames() map[string]string` renames methods. By default a peer may attach, read and
call but not write; register a `security.PermissionsManager` to decide otherwise.

## Using remote resources

```go
conn, err := ep.Connect(ctx, "ws://127.0.0.1:51018", ep.Config{}) // also tcp://, ep://, eps://
greeter, err := conn.Get(ctx, "sys/greeter")
greeter.Value("visits")                            // cached, kept up to date by the peer
reply, err := greeter.Invoke(ctx, "greet", "Ahmed") // a remote call
err = greeter.Set(ctx, "label", "hi")               // a remote write
greeter.OnProperty("visits", func(v any) { ... })
stop, err := greeter.OnEvent(ctx, "ping", func(v any) { ... }) // subscribes on first listener
```

Listeners run one at a time, in order, on a goroutine of the connection; they may call back
into the connection.

## Authentication and encryption

```go
// A server hosting the account alice and proving its own identity as "server".
auth, _ := security.NewStaticPasswordProvider(
	map[string]string{"alice": "wonderland"}, map[string]string{"server": "srv-secret"}, "server")
server := ep.NewServer(w, ep.ServerConfig{DenyAnonymous: true, AuthenticationProvider: auth,
	EncryptionProviders: []security.EncryptionProvider{security.AesGcm{}}})

// A client logging in as alice, with AES-256-GCM records after the handshake.
clientAuth, _ := security.NewStaticPasswordProvider(nil, map[string]string{"alice": "wonderland"}, "alice")
conn, err := ep.Connect(ctx, url, ep.Config{
	AuthenticationMode: packet.AuthInitializerIdentity, // or AuthResponderIdentity, AuthDualIdentity
	EncryptionMode:     packet.EncryptWithSessionKey,
	AuthenticationProvider: clientAuth, Identity: "alice",
})
```

Implement `security.PasswordStore` to back accounts with your own storage, or
`security.AuthProvider` for another protocol.

## Packages

| Package | Contents |
| --- | --- |
| `data` | TDUs, Trus, composer and parser, typed collections, indexed structures, TypeDefs, registry |
| `packet` | EP and authentication packets and their enums |
| `core` | wire errors (`core.Error`, error types and exception codes) |
| `security` | authentication sessions and providers, `password-sha3-v1`, AES-GCM, permissions |
| `resource` | hosted resources, `Property`/`Event`, `Instance`, `Warehouse`, stores, `TypeDef` |
| `ep` | `Connection`, `RemoteResource`, `Server`, sockets |

`examples/server` and `examples/client` are a runnable pair.

## Tests

```
go test ./...
```

The vector tests compare against fixtures generated from esiur-ts (shared with esiur-python and
regenerated by its `tools/gen-*.mjs`). The interop tests in `ep` start a real esiur-ts server and
client from `tools/ts-test-*.mjs`; set `ESIUR_TS_PATH` if esiur-ts is not checked out next to this
repository (it needs `npm install` there).

## License

MIT
