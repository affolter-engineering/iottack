# vuln blueborne

Scans for nearby Bluetooth devices and assesses each one against the BlueBorne
vulnerability set disclosed in September 2017.

BlueBorne is a collection of eight vulnerabilities affecting Bluetooth stacks
across Linux, Android, Windows and iOS. Unlike most Bluetooth attacks,
BlueBorne requires **no pairing, no user interaction and no prior association**
with the target device. Any device with Bluetooth enabled and within radio range
is potentially within the attack surface.

## CVE coverage

| CVE | Platform | Impact | CVSS |
|-----|----------|--------|------|
| CVE-2017-0781 | Android | RCE via BNEP heap overflow | 8.8 |
| CVE-2017-0782 | Android | RCE via AVDTP heap overflow | 8.8 |
| CVE-2017-0783 | Android | Information disclosure via PAN | 6.5 |
| CVE-2017-0785 | Android | Information disclosure via SDP | 6.5 |
| CVE-2017-1000250 | Linux (BlueZ) | Information disclosure via SDP | 6.5 |
| CVE-2017-1000251 | Linux kernel | RCE via L2CAP stack overflow | 8.0 |
| CVE-2017-8628 | Windows | MitM attack via PAN/BNEP | 8.1 |

## How detection works

The plugin cannot confirm patch status remotely. It uses observable Bluetooth
properties to identify devices likely affected by each CVE:

| Signal | Source | Infers |
|--------|--------|--------|
| Device name contains "Galaxy", "Pixel", "Huawei", etc. | `Name` property | Android |
| Device name contains "ubuntu", "raspberry", "debian", etc. | `Name` property | Linux |
| Bluetooth major class = Computer (0x01) | `Class` property | Linux |
| Bluetooth major class = Phone (0x02) | `Class` property | Android/mobile |
| Icon type = `phone` | `Icon` property | Android/mobile |
| Advertises A2DP/AVDTP UUID | `UUIDs` property | CVE-2017-0781/0782 target |
| Advertises BNEP/PAN UUID | `UUIDs` property | CVE-2017-0783/0783/8628 target |

All findings are **advisory**. A device that receives no specific CVE mapping is
still reported as "in range" because BlueBorne can target any reachable device
with Bluetooth Classic enabled.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | Scan completed (findings may still indicate exposure) |
| `fail` | Bluetooth unavailable or no adapter found |

## Severity

| Severity | Condition |
|----------|-----------|
| High | Platform identified (Android/Linux) **and** matching vulnerable profile present |
| Medium | Platform identified **or** vulnerable profile present |
| Low | Generic Bluetooth device with no specific indicators |
| Info | Device discovered but no BlueBorne indicators found |

## Requirements

- BlueZ daemon (`bluetoothd`) must be running.
- The D-Bus system bus must be accessible.
- Devices must be advertising and within radio range.

## Usage

```sh
iottack vuln blueborne [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout <SECS>` | `-t` | `15` | Scan duration in seconds |
| `--adapter <NAME>` | `-a` | first available | Bluetooth adapter to use, e.g. `hci0` |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Examples

Scan with the default 15 second window:

```sh
iottack vuln blueborne
```

Extended scan with a specific adapter and JSON output:

```sh
iottack vuln blueborne --timeout 30 --adapter hci1 --format json --output report.json
```

## Mitigation

Apply all Bluetooth security patches from September 2017 or later. Where
possible, disable Bluetooth when not in use.

| Platform | Action |
|----------|--------|
| Android | Apply the September 2017 Android Security Bulletin |
| Linux | Update kernel ≥ 4.14 and BlueZ ≥ 5.47 |
| Windows | Apply MS17-013 / KB4038788 |
| iOS | Upgrade to iOS 10 or later |
