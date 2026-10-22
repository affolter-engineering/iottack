# amqp scan

Connects to the target AMQP port using the [lapin](https://crates.io/crates/lapin)
client library and performs an AMQP 0-9-1 handshake. The outcome of the initial
connection attempt distinguishes three cases:

- **AMQP protocol error** (e.g., `ACCESS_REFUSED`): a broker is running and
  rejected the probe credentials. The service is flagged as confirmed.
- **Successful connection**: a broker is running and accepted the probe credentials.
- **IO error or timeout**: no broker is listening on that port.

## Related services

| Port | Service |
|------|---------|
| 5671 | AMQPS — TLS-encrypted AMQP |
| 5672 | AMQP — plaintext (this plugin) |
| 15672 | RabbitMQ management HTTP API and web UI |

Use the [`http/banner`](../http/http-banner.md) plugin to probe port 15672 for
the management interface.

## Severity mapping

| Finding | Severity |
|---------|----------|
| AMQP broker detected | Info |
| Cleartext AMQP on port 5672 | High |
| Default credentials accepted | Critical |
| No default credentials accepted | Info |
| Management UI hint (port 15672) | Info |

## Usage

```sh
iottack amqp scan --host <HOST> [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required)* | Target hostname or IP address |
| `--port <PORT>` | `-p` | `5672` | AMQP port |
| `--vhost <VHOST>` | `-V` | `/` | Virtual host to authenticate against |
| `--timeout-ms <MS>` | `-t` | `3000` | Connection timeout (ms) |
| `--try-creds` | - | off | Probe common default credentials |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

When `--try-creds` is set, a list of common default credentials is probed in
sequence. Each pair opens a fresh TCP connection, performs the full handshake,
and closes cleanly on success.

### Default credentials probed

| Username | Password |
|----------|----------|
| `guest` | `guest` |
| `admin` | `admin` |
| `admin` | `password` |
| `admin` | `rabbitmq` |
| `rabbitmq` | `rabbitmq` |
| `user` | `user` |
| `root` | `root` |
| `admin` | `guest` |

RabbitMQ ships with `guest`/`guest` as the built-in administrator
account. Modern versions restrict it to `localhost` connections by default,
but misconfigured or older deployments expose it on all interfaces.

## Examples

Detect the broker:

```sh
$ iottack amqp scan --host 192.168.1.100
[...]
[INFO] AMQP broker on 192.168.1.100:5672
  An AMQP 0-9-1 broker is listening on 192.168.1.100:5672.

[HIGH] Cleartext AMQP on port 5672
  AMQP 0-9-1 transmits credentials and all message payloads in plaintext.
  Use AMQPS (port 5671) with TLS.
```

Check for default credentials:

```sh
$ iottack amqp scan --host 192.168.1.100 --try-creds
[...]
[CRITICAL] Default credentials accepted: guest/guest
  The broker on 192.168.1.100:5672 accepted guest/guest for vhost '/'.
  Change this password immediately.
```

Scan a non-default virtual host:

```sh
$ iottack amqp scan --host 192.168.1.100 --vhost /production --try-creds
```

Scan an AMQPS endpoint (port 5671 - no cleartext finding):

```sh
$ iottack amqp scan --host 192.168.1.100 --port 5671 --try-creds
```

## Test environment

See [AMQP server setup](../../misc/rabbitmq.md) for instructions on running a
local RabbitMQ instance for testing.
