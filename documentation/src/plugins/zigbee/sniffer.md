# zigbee sniffer

Passively capture IEEE 802.15.4/Zigbee frames via an nRF52840 sniffer dongle
and report MAC-layer security weaknesses.

## Usage

```sh
iottack zigbee sniffer [OPTIONS]
```

## Description

Uses a Nordic Semiconductor nRF52840 USB dongle running the
[nRF Sniffer for 802.15.4](https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4)
firmware to passively capture IEEE 802.15.4 MAC frames. The dongle is
auto-detected by USB VID/PID (VID 0x1915) via Linux sysfs. The firmware
exposes a simple line-oriented shell over USB CDC-ACM; the plugin sends
`channel N` and `receive` commands and parses the
`received: HEX power: RSSI lqi: LQI time: TS` output lines.

Captured frames are parsed and analyzed for the following weaknesses:

| Check | Finding | Severity |
| --- | --- | --- |
| Data frames without MAC Security Enabled bit | Unencrypted traffic | High |
| MAC association requests observed | Device join in progress | Medium |
| PAN ID is 0x1234 | Factory-default PAN ID | High |
| PAN ID is 0xFFFF | Broadcast PAN ID in use | Medium |

Frame statistics are reported per channel: frame count, beacons, encrypted
and plaintext data frames, association events and unique PAN IDs observed.

**Note:** This plugin captures at the MAC layer only. Zigbee NWK-layer
encryption (AES-128 CCM*) is not decrypted. The absence of *MAC*-layer
security (the Security Enabled bit in the Frame Control Word) is flagged,
but NWK-layer encrypted frames still appear as secure here even if the
network key is weak.

## Options

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--port <PORT>` | `-p` | *(auto-detect)* | Serial port of the nRF52840 dongle (e.g., `/dev/ttyACM0`) |
| `--channel <CH>` | `-c` | `15` | IEEE 802.15.4 channel to sniff (11-26). Ignored when `--scan-all` is set |
| `--scan-all` | `-a` | - | Sniff all 16 Zigbee channels (11-26) sequentially, spending `duration-ms/16` on each |
| `--duration-ms <MS>` | `-d` | `5000` | Total capture duration in milliseconds |
| `--timeout-ms <MS>` | `-t` | `200` | Per-read serial timeout. Controls how quickly the loop reacts between frames |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |

## Examples

Auto-detect dongle and sniff channel 15 for 5 seconds:

```sh
iottack zigbee sniffer
```

Sniff all 16 channels for 30 seconds (about 1.9 s per channel):

```sh
iottack zigbee sniffer --scan-all --duration-ms 30000
```

Target a specific port and channel:

```sh
iottack zigbee sniffer --port /dev/ttyACM0 --channel 20 --duration-ms 10000
```
