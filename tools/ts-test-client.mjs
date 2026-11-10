// Runs a real esiur-ts client against a server (the interop tests start a Go Server and run
// this against it). The esiur-ts SOURCE is bundled with esbuild, as in ts-test-server.mjs.
//
// It prints one JSON object per line: {"phase":"attached", ...} once it has attached, subscribed and
// exercised the server, then waits for a line on stdin and prints {"phase":"final", ...} after the
// server has changed things on its own.
// Usage: node tools/ts-test-client.mjs <port> [path-to-esiur-ts] [options-json]
// options: {authenticationMode, encryptionMode, identity, password, serverPassword} (numbers are the
// AuthenticationMode / EncryptionMode values); without them the connection is anonymous.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const port = Number(process.argv[2]);
const root = resolve(process.argv[3] ?? "../esiur-ts").replaceAll("\\", "/");
const options = JSON.parse(process.argv[4] ?? "{}");
const { build } = await import(pathToFileURL(resolve(root, "node_modules/esbuild/lib/main.js")).href);

const entry = /* ts */ `
import { EpConnection } from "${root}/src/protocol/EpConnection.ts";
import { Warehouse } from "${root}/src/resource/Warehouse.ts";
import { PasswordAuthenticationProvider, IdentityPassword, PasswordHash } from "${root}/src/security/providers/index.ts";
import { AesEncryptionProvider } from "${root}/src/security/cryptography/AesEncryptionProvider.ts";
import { stringToBytes } from "${root}/src/data/DC.ts";

const options = ${JSON.stringify(options)};
// This client hosts the server account (so it can check the server) and proves its own identity.
class Accounts extends PasswordAuthenticationProvider {
  hosted = new Map([["server", PasswordAuthenticationProvider.createCredential(stringToBytes(options.serverPassword ?? "srv-secret"))]]);
  secrets = new Map([[options.identity ?? "alice", stringToBytes(options.password ?? "wonderland")]]);
  getHostedAccountCredential(identity) { return this.hosted.get(identity) ?? new PasswordHash(); }
  getSelfIdentityAndCredential() { const id = options.identity ?? "alice"; return new IdentityPassword(id, this.secrets.get(id)); }
  getSelfCredential(identity) { return this.secrets.get(identity) ?? null; }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const message = (e) => String((e && e.message) ?? e);
const print = (value) => console.log(JSON.stringify(value));

const warehouse = new Warehouse();
warehouse.registerEncryptionProvider(new AesEncryptionProvider());
const connectOptions = options.authenticationMode ? {
  authenticationMode: options.authenticationMode,
  encryptionMode: options.encryptionMode ?? 0,
  identity: options.authenticationMode === 2 ? undefined : (options.identity ?? "alice"),
  authenticationProvider: new Accounts(),
} : undefined;
let connection;
try {
  connection = await EpConnection.connect("ws://127.0.0.1:${port}", warehouse, connectOptions);
} catch (e) {
  print({ phase: "error", message: message(e) });
  process.exit(0);
}
const greeter = await connection.get("sys/greeter");
const other = await connection.get("sys/other");
const names = (members) => members.map((m) => m.name).sort();

const out = { phase: "attached" };
out.encrypted = connection.session.encryptionActive;
out.keyLength = connection.authenticationSessionKey?.length ?? 0;
out.localIdentity = connection.localAuthenticationIdentity;
out.remoteIdentity = connection.remoteAuthenticationIdentity;
out.typeName = greeter.template.className;
out.properties = names(greeter.template.properties);
out.functions = names(greeter.template.functions);
out.events = names(greeter.template.events);
out.visits0 = greeter.visits;
out.label0 = greeter.label;
out.serial0 = greeter.serial;
out.partnerId = greeter.partner?.ResourceInstanceId;
out.otherId = other.ResourceInstanceId;
out.greeterId = greeter.ResourceInstanceId;
out.cycle = other.partner?.ResourceInstanceId === greeter.ResourceInstanceId;

out.greet = await greeter.greet("TS");
out.add = await greeter.add(2, 40);
out.range = Array.from(await greeter.range(4));
out.slow = await greeter.slow("quiet");
try { await greeter.fail(); out.fail = "no error"; } catch (e) { out.fail = message(e); }
try { await greeter.add(1); out.badCall = "no error"; } catch (e) { out.badCall = message(e); }
out.echoId = (await greeter.echo(other)).ResourceInstanceId;

greeter.label = "written by ts";
await sleep(200);
out.serialWrite = "pending";

const pings = [];
const ticks = [];
await greeter.onAsync("ping", (v) => pings.push(v));
greeter.on("tick", (v) => ticks.push(v));
await sleep(100);
await greeter.fire_ping("from ts");
await greeter.fire_tick("tick from ts");
await sleep(200);
out.visitsAfterGreets = greeter.visits;
out.pings = [...pings];
out.ticks = [...ticks];
print(out);

await new Promise((resolve) => {
  process.stdin.once("data", resolve);
  process.stdin.resume();
});
await sleep(300);
print({
  phase: "final",
  visits: greeter.visits,
  label: greeter.label,
  partnerId: greeter.partner?.ResourceInstanceId ?? null,
  pings: [...pings],
  ticks: [...ticks],
});
connection.close();
process.exit(0);
`;

const dir = mkdtempSync(join(tmpdir(), "esiur-client-"));
const file = join(dir, "client.mjs");
try {
  const result = await build({
    stdin: { contents: entry, resolveDir: root, loader: "ts", sourcefile: "client.ts" },
    bundle: true, write: false, platform: "node", format: "esm", target: "es2022",
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
  console.error(error);
  process.exit(1);
}
