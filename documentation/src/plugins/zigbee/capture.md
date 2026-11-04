# zigbee capture

Capture raw IEEE 802.15.4/Zigbee frames to a PCAP file for analysis in
Wireshark or as summary to the CLI.

## Usage

```sh
iottack zigbee capture [OPTIONS]
```

## Description

The captured file can be opened in Wireshark during or after the capture.
Wireshark refreshes automatically on new packets. Full 802.15.4 and Zigbee
dissection is available out of the box. Network keys for decryption can
be added under
*Edit -> Preferences -> Protocols -> IEEE 802.15.4 -> Decryption Keys*.

Timestamps use the sniffer's own microsecond clock (the `time:` field in each
output line), anchored to the host wall clock on the first received frame.

The 2-byte FCS appended by the firmware is stripped before writing, producing
clean `DLT_IEEE802_15_4_NOFCS` records that Wireshark expects.

## Options

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--port <PORT>` | `-p` | *(auto-detect)* | Serial port of the nRF52840 dongle (e.g., `/dev/ttyACM0`) |
| `--channel <CH>` | `-c` | `15` | IEEE 802.15.4 channel to capture (11-26). Ignored when `--scan-all` is set |
| `--scan-all` | `-a` | - | Capture on all 16 Zigbee channels (11-26) sequentially, spending `duration-ms/16` on each |
| `--duration-ms <MS>` | `-d` | `30000` | Total capture duration in milliseconds |
| `--timeout-ms <MS>` | `-t` | `200` | Per-read serial timeout (ms) |
| `--pcap <FILE>` | `-P` | `zigbee_capture.pcap` | Output PCAP file path |
| `--table` | `-T` | - | Show all captured frames as an ASCII table instead of one finding per frame |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |

## Examples

Capture channel 15 for 30 seconds to the default file:

```sh
iottack zigbee capture
```

Open Wireshark on the output file immediately so it follows the live capture:

```sh
iottack zigbee capture &
wireshark zigbee_capture.pcap
```

Scan all 16 channels for 60 seconds and save to a named file:

```sh
iottack zigbee capture --scan-all --duration-ms 60000 --pcap network.pcap
```

Show a summary table of all captured frames:

```sh
iottack zigbee capture --channel 11 --duration-ms 10000 --table
```

## Wireshark decryption

To decrypt Zigbee NWK-layer traffic in Wireshark:

1. Open *Edit -> Preferences -> Protocols -> IEEE 802.15.4*
2. Under *Decryption Keys*, click *Edit* and add the network key
3. Wireshark will automatically decrypt frames that match the key

The network key can often be recovered by capturing a device join with
`iottack zigbee sniffer --scan-all` and looking for the Network Key
Transport frame during the Trust Centre join procedure.
