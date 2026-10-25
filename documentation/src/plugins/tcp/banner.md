# tcp banner

Opens a TCP connection to the target and reads the first bytes the service sends
on connection (the banner). If the service sends nothing, a set of protocol-specific
probes is tried in sequence until one matches.

The banner is compared against known signatures to identify the service. Cleartext
and unauthenticated protocols are flagged with an elevated severity.

## Identified protocols

| Protocol | Detection method | Severity |
|----------|-----------------|----------|
| SSH | Banner prefix `SSH-` | Info |
| FTP | `220 ` + server strings | High |
| Telnet | IAC option negotiation bytes | High |
| SMTP | `220 ` + ESMTP keywords | Medium |
| POP3 | `+OK ` prefix | Medium |
| IMAP | `* OK ` prefix | Medium |
| VNC | `RFB 0` prefix | High |
| HTTP | Active probe - `GET / HTTP/1.0` | Low |
| Redis | Active probe - `PING` | High |
| MQTT | Active probe - CONNECT packet | High |
| Modbus/TCP | Active probe - Read Holding Registers | High |

Unrecognized banners that contain version strings are reported as **Medium**
(information disclosure); all other unknown services are **Info**.

## Severity mapping

| Finding | Severity |
|---------|----------|
| FTP, Telnet, VNC, Redis, MQTT, Modbus/TCP | High |
| SMTP, POP3, IMAP | Medium |
| Unknown service with version disclosure | Medium |
| HTTP service | Low |
| SSH service | Info |
| Unknown service, no version info | Info |
| No banner received | Info |

## Usage

```sh
iottack network tcp-banner --host <HOST> --port <PORT> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | - | Target hostname or IP address |
| `--net <CIDR>` | `-n` | - | IPv4 CIDR subnet to sweep, e.g., `192.168.1.0/24`. Overrides `--host` |
| `--port <PORT>` | `-p` | `80` | Single TCP port, used when `--ports`/`--all-ports` are absent |
| `--ports <PORTS>` | `-P` | - | Port list or ranges: `22,80,443`, `8080-8090`, `22,8000...9000` |
| `--all-ports` | `-A` | off | Sweep all TCP ports 1-65535; overrides `--port` and `--ports` |
| `--timeout-ms <MS>` | `-t` | `3000` | Connect and read timeout (ms); use 200-500 ms for sweeps |
| `--probe <PROBE>` | - | *(empty)* | Data to send after connecting. empty means passive read |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

Port option precedence: `--all-ports` > `--ports` > `--port`.

`--host` and `--net` are mutually exclusive. `--net` takes precedence when both are given.

During subnet or port sweeps, active probes (the protocol-specific
request/response pairs for HTTP, Redis, MQTT and Modbus) are skipped.
Only the passive banner read is performed per host/port combination to
keep the sweep fast.

## Examples

Grab the banner from an SSH service:

```sh
$ iottack network tcp-banner --host 192.168.1.1 --port 22
[...]
SSH on 192.168.1.1:22
  Banner: SSH-2.0-OpenSSH_8.9p1
```

Check for an MQTT broker with no authentication:

```sh
$ iottack network tcp-banner --host 192.168.1.100 --port 1883
[...]
MQTT on 192.168.1.100:1883
  Banner: ...
  Evidence: " \u{2}\0\u{5}"
```

Sweep a /24 for open port 22 (short timeout to keep the scan fast):

```sh
$ iottack network tcp-banner --net 192.168.1.0/24 --port 22 --timeout-ms 300
[...]
SSH on 192.168.1.1:22
  Banner: SSH-2.0-OpenSSH_8.9p1
SSH on 192.168.1.42:22
  Banner: SSH-2.0-dropbear_2022.83
Open port 192.168.1.100:22
  TCP connection accepted but no banner received.
```

Scan a single host across common IoT ports:

```sh
$ iottack network tcp-banner --host 192.168.1.1 \
    --ports 22,23,80,443,502,1883,8080,8883
[...]
SSH on 192.168.1.1:22
  Banner: SSH-2.0-dropbear
Telnet on 192.168.1.1:23
  Banner: ...
Modbus/TCP on 192.168.1.1:502
  Banner: ..
```

Sweep a subnet across multiple ports:

```sh
$ iottack network tcp-banner --net 10.0.0.0/24 \
    --ports 22,80,502,1883 --timeout-ms 400
```

Full port sweep of a single target:

```sh
$ iottack network tcp-banner --host 192.168.1.1 --all-ports --timeout-ms 300
```

Send a custom probe string to a single host:

```sh
$ iottack network tcp-banner --host 192.168.1.1 --port 9999 \
    --probe "HELLO\r\n"
```
