# bacnet - find-devices

Enumerate all BACnet devices and routers reachable from the current host.

## Usage

```sh
iottack bacnet find-devices [OPTIONS]
```

## Description

Sends a BACnet Who-Is broadcast (or unicast to `--host`) and a Who-Is-Router
broadcast to discover all BACnet devices and routers on the reachable network
segment. Unlike `bacnet/scan`, no property reads are performed, making this a
fast enumeration sweep.

Equivalent to BACteria `find_devices()`.

Two discovery mechanisms run in sequence:

1. **Who-Is/I-Am**: discovers BACnet devices; each I-Am response yields device
   ID, vendor, segmentation and max APDU size.
2. **Who-Is-Router/I-Am-Router-To-Network**: discovers BACnet routers and the
   network numbers they route to, enabling lateral discovery of downstream segments.

Use `--network` to restrict the Who-Is to a specific BACnet network number routed
via the target host.

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| No devices or routers found | Info |
| Devices discovered | High |
| Routers discovered | High |

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--host <HOST>` | `-H` | *(broadcast)* | Unicast target address; omit to broadcast |
| `--port <PORT>` | `-p` | `47808` | BACnet/IP UDP port |
| `--timeout-ms <MS>` | - | `3000` | Discovery window in ms |
| `--network <NET>` | `-n` | - | BACnet network number to query via router |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack bacnet find-devices

Plugin name:    bacnet/find-devices
Execution time: 3.01 s
Status:         pass
Date:           2025-11-08 00:00:00 UTC

3 BACnet devices found
  192.168.1.50:47808  ID=1001  vendor=Siemens (16)  max-apdu=1476
  192.168.1.51:47808  ID=2002  vendor=Schneider Electric (11)  max-apdu=1476
  192.168.1.52:47808  ID=3003  vendor=Johnson Controls (5)  max-apdu=480

1 BACnet router found
  192.168.1.1:47808  networks=[200, 201, 202]
```
