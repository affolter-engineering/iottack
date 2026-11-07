# bacnet scan

Discover BACnet/IP devices and read device properties unauthenticated.

## Usage

```sh
iottack bacnet scan [OPTIONS]
```

## Description

Implements the reconnaissance approach of
[BACteria](https://github.com/cyber-defence-campus/BACteria) as an iottack plugin.

1. **Who-Is broadcast / unicast**: sends a BACnet Who-Is datagram on UDP 47808.
   Without `--host` the packet is sent as a global broadcast so every BACnet/IP
   device on the local network is queried at once. With `--host` a unicast
   Who-Is targets a single device.
2. **I-Am collection**: the plugin listens for I-Am responses for the full
   `--timeout-ms` window. Each unique responder is recorded with its device
   instance number and vendor ID.
3. **ReadProperty enumeration**: for every discovered device the plugin sends
   unauthenticated ReadProperty confirmed requests for eight Device-object
   properties: Vendor Name, Vendor ID, Object Name, Model Name, Firmware
   Revision, App Software Version, Description and Location.

BACnet provides no authentication by default (BACnet/SC adds TLS but is not
yet widely deployed). Any device that responds is a potential attack target.

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| No BACnet devices found | Info |
| Device responds to Who-Is; ReadProperty rejected | High |
| Device allows unauthenticated ReadProperty | Critical |

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--host <HOST>` | `-H` | *(broadcast)* | Target host for unicast scan |
| `--port <PORT>` | `-p` | `47808` | BACnet/IP UDP port |
| `--timeout-ms <MS>` | - | `3000` | Who-Is discovery window in ms |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack bacnet scan --host 192.168.1.50

Plugin name:    bacnet/scan
Execution time: 4.83 s
Status:         pass
Date:           2025-11-01 00:00:00 UTC

BACnet/IP device at 192.168.1.50:47808 exposes 6 properties unauthenticated
  Device accepted ReadProperty requests for 6 Device-object properties
  without any credentials: Vendor Name, Vendor ID, Object Name, Model Name,
  Firmware Revision, Description.
  Evidence:
    Address:         192.168.1.50:47808
    Device instance: 1234
    Vendor ID (IAm): 8
    Vendor Name: Siemens
    Vendor ID: 8
    Object Name: Field Panel
    Model Name: PXC001-E.D
    Firmware Revision: 2.3.1
    Description: HVAC controller lobby
```
