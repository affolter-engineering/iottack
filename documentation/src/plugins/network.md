# Network

The network plugins cover discovery and interaction at the IP/application layer,
targeting services that IoT devices expose on a local or routed network. These
plugins do not require physical access and can be run from any host with
network-layer reachability to the target.

## mDNS / DNS-SD

Multicast DNS (mDNS, RFC 6762) and DNS-Based Service Discovery (DNS-SD,
RFC 6763) allow devices to advertise and discover services on a local network
without a central DNS server. The protocol uses multicast UDP on port 5353
and is enabled by default on a large share of IoT devices, including:

- Smart home hubs and bridges (HomeKit, Matter, Zigbee gateways)
- IP cameras and NVRs
- Network printers and storage (AirPrint, SMB)
- Media renderers and speakers (Chromecast, AirPlay)
- Industrial gateways and PLCs with web interfaces

An mDNS scan reveals the device type, model, firmware version, and open service
ports. All without authentication and often without triggering any security
event on the target.

## Telnet

Telnet (RFC 854) is a plain-text remote terminal protocol dating from 1969. It
remains widely deployed on IoT devices as a debug, management and recovery
interface because it is trivial to implement in firmware.

Telnet has no built-in encryption or strong authentication. Every keystroke,
including passwords, is transmitted in cleartext. An attacker with network
access can passively capture sessions or perform a man-in-the-middle attack
without detection.

Common findings on IoT Telnet services:

- **Default credentials**: `admin/admin`, `root/root`, `root/<empty>`
- **No authentication**: the device drops directly to a shell prompt
- **Version disclosure**: banners reveal OS, kernel and BusyBox versions
- **U-Boot or recovery shells**: exposed during boot on management ports

## Plugins

| Plugin | Command | Summary |
|--------|---------|---------|
| [network mdns-scan](./network/mdns-scan.md) | `iottack network mdns-scan` | Discover mDNS/DNS-SD services on the local network |
| [network telnet](./network/telnet.md) | `iottack network telnet` | Connect to a Telnet service and detect banners, login prompts, and default credentials |

## Typical workflow

1. **Discover services**: scan the local network segment for mDNS
   advertisements to build an inventory of devices and open ports.

   ```sh
   iottack network mdns-scan
   ```

2. **Check Telnet**: for each device that advertises a management interface
   or that has port 23 open, probe for default credentials.

   ```sh
   iottack network telnet --host 192.168.1.1 --try-creds
   ```
