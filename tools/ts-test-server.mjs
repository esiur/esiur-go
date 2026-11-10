// Starts a real esiur-ts EpServer (WebSocket) for the interop tests: it bundles the esiur-ts SOURCE
// with esbuild, serves two resources (sys/greeter, sys/other) that refer to each other, prints {"port": ..., "greeterId": ..., "otherId": ...} on one
// line, and runs until stdin closes.
// Usage: node tools/ts-test-server.mjs [path-to-esiur-ts]
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(process.argv[2] ?? "../esiur-ts").replaceAll("\\", "/");
const { build } = await import(pathToFileURL(resolve(root, "node_modules/esbuild/lib/main.js")).href);

const entry = /* ts */ `
import { EpServer } from "${root}/src/protocol/EpServer.ts";
import { Warehouse } from "${root}/src/resource/Warehouse.ts";
import { MemoryStore } from "${root}/src/stores/MemoryStore.ts";
import { Resource } from "${root}/src/resource/Resource.ts";
import { Export, AutoDelivered, event, type EventSource } from "${root}/src/resource/decorators.ts";
import { t } from "${root}/src/data/descriptors.ts";
import { Ruling } from "${root}/src/security/permissions/Ruling.ts";
import { PasswordAuthenticationProvider, IdentityPassword, PasswordHash } from "${root}/src/security/providers/index.ts";
import { AesEncryptionProvider } from "${root}/src/security/cryptography/AesEncryptionProvider.ts";
import { stringToBytes } from "${root}/src/data/DC.ts";

// Writing a property is denied unless a permissions manager allows it; this one allows everything.
class AllowAll {
  managerCategory = "permissions" as const;
  settings = undefined;
  applicable() { return Ruling.Allowed; }
  initialize() { return true; }
}

// Password accounts: clients log in as alice/wonderland; this node proves itself as server/srv-secret.
class Accounts extends PasswordAuthenticationProvider {
  hosted = new Map([["alice", PasswordAuthenticationProvider.createCredential(stringToBytes("wonderland"))]]);
  secrets = new Map([["server", stringToBytes("srv-secret")]]);
  getHostedAccountCredential(identity) { return this.hosted.get(identity) ?? new PasswordHash(); }
  getSelfIdentityAndCredential() { return new IdentityPassword("server", this.secrets.get("server")); }
  getSelfCredential(identity) { return this.secrets.get(identity) ?? null; }
}

class Greeter extends Resource {
  @Export(t.i32) accessor visits = 0;
  @Export(t.string) accessor label = "hello";
  @Export(t.resource) accessor partner: Resource | null = null;
  @Export(t.string) ping: EventSource<string> = event<string>();
  @Export(t.string) @AutoDelivered() tick: EventSource<string> = event<string>();

  @Export(t.string, [t.string]) greet(name: string): string {
    this.visits++;
    return "Hi " + name;
  }
  @Export(t.void, [t.string]) firePing(message: string): void {
    this.ping.emit(message);
  }
  @Export(t.void, [t.string]) fireTick(message: string): void {
    this.tick.emit(message);
  }
  @Export(t.list(t.i32), [t.i32]) range(count: number): number[] {
    return Array.from({ length: count }, (_, i) => i);
  }
  @Export(t.resource, [t.resource]) echo(resource: Resource): Resource {
    return resource;
  }
  @Export(t.i32, [t.i32, t.i32]) add(a: number, b: number): number {
    return a + b;
  }
  @Export(t.void) fail(): void {
    throw new Error("boom");
  }
}

const warehouse = new Warehouse();
warehouse.registerManager(new AllowAll() as never, true);
warehouse.registerAuthenticationProvider(new Accounts());
warehouse.registerEncryptionProvider(new AesEncryptionProvider());
await warehouse.put("sys", new MemoryStore());
const greeter = await warehouse.put("sys/greeter", new Greeter());
const other = await warehouse.put("sys/other", new Greeter());
await warehouse.open();
// Two resources that refer to each other.
greeter.partner = other;
other.partner = greeter;
const server = await EpServer.listen({ port: 0, host: "127.0.0.1", warehouse });
console.log(JSON.stringify({ port: server.port, greeterId: greeter.instance!.id, otherId: other.instance!.id }));

process.stdin.resume();
process.stdin.on("end", async () => {
  await server.close();
  process.exit(0);
});
`;

const dir = mkdtempSync(join(tmpdir(), "esiur-server-"));
const file = join(dir, "server.mjs");
try {
  const result = await build({
    stdin: { contents: entry, resolveDir: root, loader: "ts", sourcefile: "server.ts" },
    bundle: true, write: false, platform: "node", format: "esm", target: "es2022",
    // ws is CommonJS and optionally requires native add-ons; the bundle needs a `require`.
    external: ["bufferutil", "utf-8-validate"],
    banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
    tsconfigRaw: { compilerOptions: { target: "ES2022", useDefineForClassFields: true } },
    logLevel: "error",
  });
  writeFileSync(file, result.outputFiles[0].text);
  process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
  await import(pathToFileURL(file).href);
} catch (error) {
  rmSync(dir, { recursive: true, force: true });
  throw error;
}
