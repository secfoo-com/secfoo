# Runtime probe ↔ sensor protocol (v1)

Every runtime gets its own in-process **probe**: Python, Node.js, JVM, .NET,
Go, Ruby, PHP and so on. All probes talk to the same **sensor** (`secfoo
sensor`, #67) in the same way. This document is that contract. A probe for a
new runtime can be built from this page and checked with the conformance kit,
without reading another probe's code.

- **Machine-readable schemas:**
  [`src/secfoo/runtime/protocol.schema.json`](../src/secfoo/runtime/protocol.schema.json)
  for control messages, and
  [`src/secfoo/runtime/evidence.schema.json`](../src/secfoo/runtime/evidence.schema.json)
  for event lines.
- **Reference probe:** `secfoo.sensor` (Python).
- **Design rules:** see #51. They apply to every probe.

## 1. Activation

A probe is **inert unless `SECFOO_SENSOR=1` is set**: no hooks, no threads,
no connections, no files. Installing secfoo or a probe package never activates
anything. The conformance kit checks this.

## 2. Configuration

| Variable | Meaning |
|---|---|
| `SECFOO_SENSOR=1` | Required to do anything at all. |
| `SECFOO_SENSOR_ADDR` | Where to send events (§3). |
| `SECFOO_EVENTS_OUT` | A file to write when `SECFOO_SENSOR_ADDR` is unset. `{pid}` expands to the process id. |
| `SECFOO_WATCHLIST` | The watchlist file. Re-read when its mtime changes, checked at most every 30 s. |
| `SECFOO_FLUSH_INTERVAL` | Seconds between flushes, until a sensor's `welcome` says otherwise (default 10). |
| `SECFOO_SENSOR_KEY` | An optional shared key for `tcp://` (§4). |
| `SECFOO_API_KEY_FILE` / `SECFOO_API_KEY`, `SECFOO_PROJECT`, `SECFOO_APP`, `SECFOO_ENV` | Direct mode only (§3). |

## 3. Transport

One variable, `SECFOO_SENSOR_ADDR`, picks the transport:

| Value | Use it for |
|---|---|
| `unix:///var/run/secfoo/sensor.sock` (default on Linux/macOS) | A host daemon, or a sidecar sharing a volume. |
| `tcp://127.0.0.1:7461` | Sidecars that share a network namespace but not a filesystem: a K8s pod, an ECS/Fargate task, Cloud Run, Azure Container Apps, a Nomad group. **Loopback only.** A probe must refuse a routable host. |
| `npipe:////./pipe/secfoo-sensor` (default on Windows) | Windows hosts and Windows containers. |
| `https://secfoo.internal` | **Direct mode**, when no second process can run (serverless, single-process PaaS). The probe POSTs gzip NDJSON batches to `POST /api/runtime/v1/events?project=&app=&env=` with `Authorization: Bearer <key>`, using the same API key as the CLI. |
| `file:///path/events.ndjson` | Offline. Ingest the file later with `secfoo runtime ingest`. |

The sensor listens only on loopback or local IPC, never on a routable address.
A probe opens **no connection other than the one `SECFOO_SENSOR_ADDR` names**.

## 4. Messages

A connection is a stream of **newline-framed JSON objects**, one per line,
UTF-8, with no line longer than 64 KiB.

```
probe  → sensor   {"type":"hello", ...}
probe  → sensor   {"type":"auth","key":"..."}          (tcp:// with SECFOO_SENSOR_KEY only)
sensor → probe    {"type":"welcome", ...}
probe  → sensor   #53 event lines: session, load, hit  (repeated on every flush)
sensor → probe    {"type":"slow","sample_every":4}     (any time, optional)
```

| Message | Direction | Fields |
|---|---|---|
| `hello` | probe → sensor, the first line on every connection | `protocol` (1), `runtime` (`python` `node` `jvm` `dotnet` `go` `rust` `ruby` `php` `native`), `runtime_version`, `probe_version`, `pid`, `host` (host or pod name) |
| `auth` | probe → sensor, straight after `hello`, `tcp://` only | `key`: the value of `SECFOO_SENSOR_KEY`. Other containers in a pod share loopback, so the sensor may require it. |
| `welcome` | sensor → probe | `protocol` (the accepted version), `flush_interval` (seconds; probes adopt it); optional `watchlist_version` and `watchlist_path` |
| `slow` | sensor → probe | `sample_every` (≥ 1): flush less often and sample more coarsely until reconnecting |
| event lines | probe → sensor | Exactly the `session` / `load` / `hit` lines of the runtime evidence format (`docs/REFERENCE.md` → *Runtime evidence*) |

**Running totals.** Each flush resends the session line and the session's
running totals. A hit's `count` is the total so far for (fingerprint, symbol,
route). The sensor and server **replace** values, never add them, so a
resent batch is harmless.

**Privacy (#51 rule 3).** Lines carry function identity, counts, timestamps,
`file:line` frames of app code (plus the vulnerable function itself), a
route **template** and an anonymous/authenticated flag. They never carry
argument or return values, local variables, request bodies, concrete URLs,
query strings, header values or user identities.

## 5. Failure behaviour

- **Fail-open.** An error inside the probe disables the probe and never
  reaches the app. The app must never crash, block or slow down noticeably.
  Target: at most 1 ms p99 added per request.
- **No sensor.** If the sensor is gone, the probe drops that flush's events,
  counts the drops, and reconnects on the next flush. It never blocks or
  retries on a request path. All I/O happens on a background flush thread or
  timer.
- **Bounded.** Memory is bounded by the watchlist and the size of the app, not
  by traffic: hits are aggregated in place, and an outgoing queue that fills
  up drops.
- **Direct mode** flushes at the end of each invocation (serverless) or on the
  interval, with a hard cap of 200 ms per flush, so a cold start or shutdown
  never waits on the network.
- **Workers.** Each process (forked or spawned worker) is its own session,
  with its own `session.id`.

## 6. Conformance kit

```bash
secfoo sensor conformance -- <command that starts your sample app with the probe loaded>
# the reference Python probe:
secfoo sensor conformance -- python -m secfoo.sensor -m secfoo.runtime.conformance.sample_app
```

The kit writes a watchlist containing `--symbol` (default
`secfoo.runtime.conformance.vulnerable.parse`; pass your runtime's equivalent
in its #52 notation, with `--ecosystem`). It then starts a fake sensor on
`tcp://127.0.0.1:<port>` and runs the command once per step. The step is
passed in `SECFOO_CONFORMANCE_STEP`.

**Sample app contract.** Your sample app reads the step, does exactly this,
prints anything, and exits 0:

| Step | The app must… |
|---|---|
| `call` | call the watched function 3 times |
| `nocall` | call only an unwatched function |
| `request` | handle one request to the concrete URL `/users/8675309?token=<S>` (route template `GET /users/{id}`) with header `Authorization: Bearer <S>`, passing both to the watched function, where `<S>` is `SECFOO_CONFORMANCE_SENTINEL` |
| `slow` | keep calling the watched function for ~1.5 s (the kit kills its sensor meanwhile) |
| `loop` | call the watched function `SECFOO_CONFORMANCE_N` times |

**Checks.** Every line in every step must validate against the schemas.

| Check | Passes when |
|---|---|
| `inert` | With `SECFOO_SENSOR` unset, the probe makes no connection and the app exits 0. |
| `call` | The first line is `hello`, there is a `session` line, and the watched symbol has a total `count` of 3. |
| `nocall` | There is a session but no hit. |
| `privacy` | No sentinel value, concrete URL path, query string or `Authorization` value appears on the wire. |
| `fail-open` | The app finishes and exits 0 although the sensor died mid-run. |
| `overhead` | The marginal cost of a watched call (measured from two loop sizes, so start-up doesn't count) is at most `--max-call-overhead-us` (default 50 µs), and the probe's one-time start-up and exit work is under `--max-startup-seconds` (default 5 s). |

A runtime probe issue is **done** only when its probe passes this kit. CI runs
it against the reference Python probe on every push.

## 7. Versioning

`hello.protocol` and `welcome.protocol` are `1`. A future incompatible
change bumps the version. A sensor that doesn't support a probe's version
closes the connection, and the probe then behaves as if the sensor were gone
(§5).
