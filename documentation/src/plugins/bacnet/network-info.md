# bacnet - network-info

Show BACnet network link details, addressing, and router topology.

## Usage

```sh
iottack bacnet network-info --host <HOST> [OPTIONS]
```

## Description

Reads network-related information from a BACnet/IP device in three steps:

1. **Device addressing**: reads addressing and transport parameters
   from the I-Am response: UDP address, device ID, vendor identity,
   max APDU, segmentation and routing information.
2. **Network Port objects**: enumerates Network Port objects (ASHRAE
   135 clause 12.56) and reads their IP address, subnet mask, default
   gateway, UDP port, DHCP configuration, MAC address and link speed.
3. **Router discovery**: sends Who-Is-Router to the target to discover
   any BACnet routers it knows about, including the network numbers they
  route to.

Equivalent to BACteria `network_info()`. Exposed network topology is flagged
High severity.

### Network Port properties read

| Property | Description |
| -------- | ----------- |
| Object Name | Port name |
| Description | Port description |
| Network Type | IP, MS/TP, Ethernet, etc. |
| Network Number | BACnet network number |
| MAC Address | MAC address |
| IP Address | IPv4 address |
| IP Subnet Mask | Subnet mask |
| IP Default Gateway | Default gateway |
| IP DNS Server | DNS server addresses |
| BACnet IP UDP Port | BACnet/IP UDP port |
| IP DHCP Enable | Whether DHCP is active |
| Link Speed | Link speed |

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| Device addressing exposed | High |
| Network Port properties readable | High |
| Routers discovered | High |

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--host <HOST>` | `-H` | *(required)* | Target BACnet/IP device |
| `--port <PORT>` | `-p` | `47808` | BACnet/IP UDP port |
| `--timeout-ms <MS>` | - | `5000` | Per-request timeout in milliseconds |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack bacnet network-info --host 192.168.1.50

Plugin name:    bacnet/network-info
Execution time: 5.82 s
Status:         pass
Date:           2026-10-18 00:00:00 UTC

BACnet device addressing exposed at 192.168.1.50:47808
  UDP address:   192.168.1.50:47808
  Device ID:     1001
  Vendor:        Siemens (ID 16)
  Max APDU:      1476
  Segmentation:  NoSegmentation

Network Port NetworkPort:0 exposes 8 network properties at 192.168.1.50:47808
  Object Name: ETH1
  Network Type: 5
  IP Address: 192.168.1.50
  IP Subnet Mask: 255.255.255.0
  IP Default Gateway: 192.168.1.1
  BACnet IP UDP Port: 47808
  IP DHCP Enable: false
  Link Speed: 100000000

1 BACnet router discovered from 192.168.1.50:47808
  192.168.1.1:47808 → networks [200, 201]
```
