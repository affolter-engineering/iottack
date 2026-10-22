# vulns bluefi CVE-2025-27840 (BlueFi)

**CVE-2025-27840** affects ESP32 Bluetooth firmware. When an ESP32 is
connected via USB in HCI (Host Controller Interface) mode, the full HCI
command set is exposed with no authentication. This includes undocumented
Espressif vendor-specific commands (OGF 0x3F) that provide:

- **Arbitrary memory read**: extract RAM, ROM, or flash content including
  cryptographic keys, Wi-Fi credentials, and NVS secrets.
- **Arbitrary memory write**: overwrite runtime state, disable security
  checks, or inject code.

The plugin:

1. Opens the ESP32 serial port and sends `HCI_Reset` to confirm HCI mode.
2. Probes the two known-dangerous OCFs (0x001 read, 0x002 write) and flags
   any that respond with a non-"unknown command" status.
3. Sweeps vendor OCF 0x000 through `--ocf-end` (default 15) to enumerate
   the broader attack surface.

**HCI command structure**:

```text
[0x01][opcode_lo][opcode_hi][param_len][params...]
```

For vendor commands (OGF 0x3F): `opcode = 0xFC00 | OCF`

## Checks performed

| Check | Finding | Severity |
|---|---|---|
| Device responds to HCI_Reset | HCI interface reachable | Medium |
| OCF 0x001 responsive | Arbitrary memory read | Critical |
| OCF 0x002 responsive | Arbitrary memory write | Critical |
| Any OCF in sweep responsive | Additional attack surface | High |
| No responsive commands found | Not vulnerable / patched | Info |

## Usage

```sh
iottack vulns bluefi --port /dev/ttyUSB1 [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--port <PORT>` | `-p` | *(required)* | Serial port of the ESP32 in HCI mode |
| `--baud-rate <BAUD>` | `-b` | `115200` | Serial baud rate |
| `--timeout-ms <MS>` | `-t` | `200` | Per-command response timeout |
| `--ocf-end <N>` | `-e` | `15` | Last OCF to sweep (max 1023 for full scan) |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |

## Examples

Quick targeted probe (known dangerous OCFs only, ~3 s):

```sh
iottack vulns bluefi --port /dev/ttyUSB1
```

Full vendor command enumeration (~200 s):

```sh
iottack vulns bluefi --port /dev/ttyUSB1 --ocf-end 1023
```

Save as JSON:

```sh
iottack vulns bluefi --port /dev/ttyUSB1 --output bluefi.json --format json
```

## Mitigation

- In production firmware, disable the HCI UART interface:
  set `CONFIG_BT_HCI_UART=n` in `sdkconfig`.
- Apply the Espressif patch that restricts vendor command access to
  authenticated channels (available in ESP-IDF ≥ 5.x with the security fix).
- Reference: <https://nvd.nist.gov/vuln/detail/CVE-2025-27840>
