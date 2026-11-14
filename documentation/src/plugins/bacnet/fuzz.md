# bacnet - fuzz

Send malformed BACnet/IP payloads to a device and report anomalous responses.

## Usage

```sh
iottack bacnet fuzz --host <HOST> [OPTIONS]
```

## Description

Sends a suite of crafted malformed BACnet/IP packets to the target device and
classifies each response as a normal Error/Reject/Abort PDU, an anomalous PDU
type or a potential crash indicator. A liveness check runs before and after
the payload set. if the device stops responding, a Critical DoS finding is raised.

Based on the mutation strategy from [BACteria](https://github.com/cyber-defence-campus/BACteria) `fuzzer.py`.

### Payload categories

| Category | Description |
| -------- | ----------- |
| Truncated APDU | Empty, 1-byte, 2-byte Confirmed-Request frames |
| ReadProperty mutations | Max instance (0x3FFFFF), invalid object type (1023), property ID 0xFFFF, invoke-id 0xFF |
| Segmentation flags | SEG bit set without segmentation headers, MOR bit set |
| WriteProperty | Attempts to overwrite Device Object Name and AnalogInput:0 Present Value |
| DeviceCommunicationControl | Tries to permanently disable device communications |
| ReinitializeDevice | Attempts cold-start and warm-start restarts |
| ReadPropertyMultiple ALL | Requests all properties in one APDU |
| Who-Is extremes | Unrestricted Who-Is broadcast |
| BVLC anomalies | Wrong function code, length mismatch, broadcast function to unicast, garbage prefix |
| Boundary APDUs | 64/256/1024/1025 zero-bytes, all 0xFF |

### Response classification

Each response is decoded into a descriptive string before pattern matching:

| Response type | Description shown |
| ------------- | ----------------- |
| Simple-ACK | `bacnet-simple-ack` |
| Complex-ACK | `bacnet-complex-ack` |
| Error PDU | `bacnet-error class=N code=N` |
| Reject PDU | `bacnet-reject reason=N (label)` |
| Abort PDU | `bacnet-abort reason=N (label)` |
| Malformed BVLC | `invalid-bvlc-response` |
| No APDU found | `no-apdu-in-response` |

Patterns flagged as interesting: `bacnet-reject`, `bacnet-abort`, `overflow` (buffer-overflow
abort reason), `bacnet-unknown`, `invalid-bvlc`, `no-apdu`, plus any `--pattern` overrides.

### Severity mapping

| Finding | Severity |
| ------- | -------- |
| No anomalous responses | Info |
| Reject/Abort PDU received | Medium |
| Buffer-overflow abort reason | Critical |
| Device unresponsive after fuzzing (DoS) | Critical |

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--host <HOST>` | `-H` | *(required)* | Target BACnet/IP device |
| `--port <PORT>` | `-p` | `47808` | BACnet/IP UDP port |
| `--timeout-ms <MS>` | - | `1000` | Per-packet response timeout |
| `--iterations <N>` | - | `1` | Times to repeat the full payload set |
| `--delay-ms <MS>` | `-d` | `50` | Inter-packet delay in ms |
| `--wordlist <PATH>` | `-w` | - | File of additional APDU payloads (one hex or binary line each) |
| `--pattern <STR>` | - | - | Extra response pattern to flag as interesting |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack bacnet fuzz --host 192.168.1.50 --delay-ms 100

Plugin name:    bacnet/fuzz
Execution time: 42.10 s
Status:         fail
Date:           2025-10-14 00:00:00 UTC

Interesting response to 'reinitialize-coldstart' payload
  192.168.1.50:47808 responded with patterns [bacnet-reject] after receiving the 'reinitialize-coldstart' payload.
  bacnet-reject reason=9 (unrecognized-service)

Interesting response to 'device-comm-control-disable' payload
  192.168.1.50:47808 responded with patterns [bacnet-reject] after receiving the 'device-comm-control-disable' payload.
  bacnet-reject reason=9 (unrecognized-service)

Interesting response to 'apdu-1025-zeros' payload
  192.168.1.50:47808 responded with patterns [bacnet-abort, overflow] after receiving the 'apdu-1025-zeros' payload.
  bacnet-abort reason=1 (buffer-overflow overflow)
```

## Notes

- **Rate limiting**: use `--delay-ms` to avoid overwhelming devices with slow BACnet stacks.
- **DoS risk**: `reinitialize-coldstart` and `device-comm-control-disable` payloads may disrupt live devices.
- **Wordlist format**: each line is treated as raw APDU bytes if the line starts with `0x81` (full packet), otherwise wrapped in a valid BVLC/NPDU unicast frame.
