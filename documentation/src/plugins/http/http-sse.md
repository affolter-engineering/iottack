# http-sse

Connects to an HTTP EventSource endpoint and keeps the connection open for a
configurable duration, collecting Server-Sent Events as they arrive.
The plugin analyses the stream for security issues including open access,
cleartext transmission, CORS policy, event rate, event types and potentially
sensitive data disclosed in event payloads.

The [SSE/EventSource](https://html.spec.whatwg.org/multipage/server-sent-events.html)
protocol is commonly used by IoT firmware to push sensor readings, device
state, and log messages to browser-based dashboards over a persistent HTTP
connection.

## Checks performed

| Check | Finding | Severity |
|-------|---------|----------|
| HTTP status 401 or 403 | Access denied | Info |
| HTTP status other than 200 | Unexpected status | Medium |
| `Content-Type` is not `text/event-stream` | Wrong content type | Medium |
| Endpoint on port 80 | SSE stream over cleartext HTTP | High |
| Endpoint reachable without credentials | Open access | Medium |
| `Access-Control-Allow-Origin: *` | Wildcard CORS policy | Medium |
| `Access-Control-Allow-Origin` set to specific origin | CORS restricted | Info |
| No `Access-Control-Allow-Origin` header | No CORS header | Info |
| Events received | Event count and rate | Info |
| Unique event type names | Event types | Info |
| Payload contains sensitive keywords | Sensitive data in stream | High |
| First event content | Event sample | Info |

Sensitive keywords checked in event payloads: `password`, `token`, `secret`,
`key`, `auth`, `credential`, `private`, `serial`.

## Usage

```sh
iottack http http-sse --host <HOST> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required)* | Target hostname or IP address |
| `--port <PORT>` | `-p` | `80` | TCP port |
| `--path <PATH>` | `-u` | `/events` | EventSource endpoint path |
| `--timeout-ms <MS>` | `-t` | `5000` | Connection timeout (ms) |
| `--duration-s <SECS>` | `-d` | `10` | How long to collect events (seconds) |
| `--max-events <COUNT>` | `-n` | `100` | Maximum number of events to collect |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Examples

Probe a device's default event stream for 10 seconds:

```sh
$ iottack http http-sse --host 192.168.1.1
```

Target a non-standard path and port, collect for 30 seconds:

```sh
$ iottack http http-sse --host 192.168.1.1 --port 8080 --path /api/events --duration-s 30
```

Collect up to 50 events and save the result as JSON:

```sh
$ iottack http http-sse --host 192.168.1.1 --max-events 50 --output result.json --format json
```

Check a device running an ESPHome web server (default port 80, path `/events`):

```sh
$ iottack http http-sse --host esphome-device.local
```
