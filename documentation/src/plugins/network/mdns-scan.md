# network mdns-scan

Browses the local network for mDNS/DNS-SD service announcements and reports
resolved instances with hostname, IP address, port and TXT records.

All service types are queried in parallel. Each query sends a probe every
second until the timeout expires. Insecure protocols are flagged at higher
severity:

| Service type | Label | Severity |
|---|---|---|
| `_telnet._tcp.local` | Telnet | High |
| `_ftp._tcp.local` | FTP | Medium |
| `_http._tcp.local` | HTTP | Low |
| `_https._tcp.local` | HTTPS | Info |
| `_ssh._tcp.local` | SSH | Info |
| `_mqtt._tcp.local` | MQTT | Info |
| `_coap._udp.local` | CoAP | Info |
| `_hap._tcp.local` | HomeKit (HAP) | Info |
| `_matter._tcp.local` | Matter | Info |
| `_googlecast._tcp.local` | Chromecast | Info |

## Usage

```sh
iottack network mdns-scan [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout-secs <SECS>` | `-t` | `5` | Seconds to listen for responses |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack network mdns-scan --timeout-secs 10

Plugin name:    network/mdns-scan
Execution time: 10.01 s
Status:         pass
Date:           2026-10-17 00:00:00 UTC

HTTP: mydevice.local
  Host: mydevice.local | Address: 192.168.1.42 | Port: 80

SSH: printer.local
  Host: printer.local | Address: 192.168.1.55 | Port: 22
```
