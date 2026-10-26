# modbus device-info

Connects to a Modbus device and performs two checks:

1. **Connectivity probe**: reads holding registers 0–3 via FC03 to confirm the
   device accepts unauthenticated connections and returns data.
2. **FC43 MEI identification**: sends a Read Device Identification request
   (function code 43, MEI type 14) to retrieve vendor name, product code,
   firmware revision and other identification strings.

Both checks run over a single connection. If FC43 is not supported or returns
no objects, the connectivity finding is still reported.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | Connection accepted (device is reachable and responded) |
| `fail` | Could not connect |

## Severity classification

| Severity | Condition |
|----------|-----------|
| High | Unauthenticated connection accepted |
| High | FC43 MEI identification objects returned |
| Info | FC43 not supported or returned no objects |
| Info | Connection failed |

## Usage

```sh
iottack modbus device-info --host <HOST> [OPTIONS]
iottack modbus device-info --serial <DEVICE> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required or --serial)* | Target hostname or IP for Modbus/TCP |
| `--tcp-port <PORT>` | - | `502` | Modbus/TCP port |
| `--serial <DEVICE>` | `-s` | *(required or --host)* | Serial device for Modbus RTU (e.g., `/dev/ttyUSB0`) |
| `--baud <BAUD>` | - | `9600` | Baud rate for RTU serial |
| `--unit <ID>` | `-u` | `1` | Modbus unit/slave ID (1–247) |
| `--timeout-ms <MS>` | `-t` | `3000` | Timeout in milliseconds |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## MEI identification objects

FC43 MEI type 14 defines the following object IDs:

| ID | Label |
|----|-------|
| `0x00` | VendorName |
| `0x01` | ProductCode |
| `0x02` | MajorMinorRevision |
| `0x03` | VendorUrl |
| `0x04` | ProductName |
| `0x05` | ModelName |
| `0x06` | UserApplicationName |
| `0x07`–`0x7F` | Reserved |
| `0x80`–`0xFF` | DeviceSpecific |

The plugin tries all three conformity levels (basic `0x01`, regular `0x02`
and extended `0x03`) and returns the first non-empty response.

## Examples

Identify a device over TCP:

```sh
iottack modbus device-info --host 192.168.1.100
```

Non-standard port:

```sh
iottack modbus device-info --host 192.168.1.100 --tcp-port 5020
```

Identify over RTU serial, unit ID 3:

```sh
iottack modbus device-info --serial /dev/ttyUSB0 --baud 19200 --unit 3
```

Save result as JSON:

```sh
iottack modbus device-info --host 192.168.1.100 \
  --format json --output device-info.json
```

## Example output

```text
Plugin name:    modbus/device-info
Execution time: 0.42 s
Status:         pass

[HIGH] Modbus/TCP: unauthenticated connection accepted (unit 1)
  Device at 192.168.1.100:502 accepted a Modbus connection without
  authentication. Holding registers 0-3: [0x0000, 0x0001, 0x0000, 0x0042]
  Evidence: "Holding registers 0-3: [0x0000, 0x0001, 0x0000, 0x0042]"

[HIGH] Modbus/TCP: device identification retrieved via FC43 MEI (unit 1)
  Device exposes identification strings without authentication:
  VendorName: Acme Corp; ProductCode: PLC-4000; MajorMinorRevision: 2.1.0
  Evidence:
    0x00 VendorName: Acme Corp
    0x01 ProductCode: PLC-4000
    0x02 MajorMinorRevision: 2.1.0
    0x04 ProductName: Industrial Controller
```
