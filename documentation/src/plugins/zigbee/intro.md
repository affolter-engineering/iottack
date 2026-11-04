# Zigbee plugins

Zigbee is an IEEE 802.15.4-based wireless mesh protocol widely used in smart
home, building automation and industrial IoT devices. It operates in the
2.4 GHz ISM band across 16 channels (11-26) and is defined by the Zigbee
Alliance (now CSA).

## Hardware

Both Zigbee plugins require a Nordic Semiconductor nRF52840 USB dongle running
the [nRF Sniffer for 802.15.4](https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4)
firmware.

Recognized USB VID/PIDs (VID 0x1915, Nordic Semiconductor ASA):

| PID | Mode |
| --- | --- |
| 0x520F | nRF52840 Dongle - application (sniffer) mode |
| 0xCA37 | nRF52840 Dongle - DFU bootloader mode |
| 0x154A | nRF52 USB Product (generic) |
| 0x154B | nRF Sniffer for 802.15.4 official firmware |

The dongle is detected automatically by USB VID/PID via Linux sysfs. Use
`--port` to override auto-detection when multiple dongles are present.

## Plugins

| Plugin | Command | Purpose |
| --- | --- | --- |
| [sniffer](./sniffer.md) | `iottack zigbee sniffer` | Passive 802.15.4 frame capture with MAC-layer security analysis |
| [capture](./capture.md) | `iottack zigbee capture` | Capture raw 802.15.4 frames to a PCAP file for Wireshark |
