# ble write

Writes a value to a specific GATT characteristic on a Bluetooth Low Energy
device or fuzzes it with the built-in payload set.

The plugin connects to the given device, locates the characteristic by UUID
across all GATT services and operates in one of two modes:

**Single-write mode** (default): writes the supplied `--value` once and reports
success or failure. The value is treated as a UTF-8 string. Pass `--hex` to
supply raw bytes.

**Fuzz mode** (`--fuzz`): iterates the built-in payload set (null bytes, long
strings, format strings, boundary values, control characters) and writes each
one to the characteristic. After each write the characteristic is read back if
it is readable, and the response is scanned for error strings, crash indicators
and shell prompts. A `--wordlist` or `--charset` can replace the built-in set.

Findings are classified as follows:

| Finding | Severity | Condition |
|---------|----------|-----------|
| Write successful | Info | Single write completed |
| Write failed | Low | Write rejected by the device |
| Interesting response | Medium–Critical | Fuzz response matched a pattern |
| No interesting responses | Info | Fuzz completed with no matches |
| Characteristic not writable | Low | Characteristic lacks write property |
| Characteristic not found | Info | UUID absent from device profile |
| Cannot connect | Info | Device unreachable or out of range |
| Bluetooth not available | Info | BlueZ daemon unreachable |

## Requirements

- BlueZ daemon (`bluetoothd`) must be running.
- The D-Bus system bus must be accessible (no special privileges required).
- The target device must be advertising and within range.

## Usage

```sh
iottack ble write --address <ADDR> --characteristic <UUID> --value <DATA>
iottack ble write --address <ADDR> --characteristic <UUID> --fuzz
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--address <ADDR>` | `-d` | required | Bluetooth address of the target device |
| `--characteristic <UUID>` | `-c` | required | GATT characteristic UUID to write |
| `--value <DATA>` | `-V` | `""` | Value to write (ignored with `--fuzz`) |
| `--hex` | `-x` | off | Treat `--value` as hex bytes, e.g., `ff00ab` |
| `--no-response` | `-n` | off | Write-without-response for every write |
| `--adapter <NAME>` | `-a` | first available | Adapter to use, e.g., `hci0` |
| `--no-disconnect` | - | off | Leave device connected after the operation |
| `--fuzz` | `-f` | off | Enable fuzz mode |
| `--iterations <N>` | - | `1` | Times to repeat the payload set (fuzz mode) |
| `--charset <CHARS>` | - | - | Characters to fuzz (fuzz mode) |
| `--length <N>` | `-l` | `16` | Max repeat length for charset payloads |
| `--wordlist <PATH>` | `-w` | - | Wordlist file. Replaces built-in payloads |
| `--delay-ms <MS>` | - | `0` | Delay between payloads in ms (fuzz mode) |
| `--suffix <BYTES>` | `-s` | - | Bytes appended to every payload, e.g., `\r\n` |
| `--pattern <STRING>` | - | - | Extra response pattern to flag (fuzz mode) |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Examples

Write the string `R` to set an LED color on the IoTTack target board:

```sh
iottack ble write \
  --address DD:EE:FF:44:55:66 \
  --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
  --value R
```

Write raw bytes using hex notation:

```sh
iottack ble write \
  --address DD:EE:FF:44:55:66 \
  --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
  --value "52 00" --hex
```

Fuzz with the built-in payload set:

```sh
iottack ble write \
  --address DD:EE:FF:44:55:66 \
  --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
  --fuzz
```

Fuzz with a custom wordlist and a 50 ms delay between payloads:

```sh
iottack ble write \
  --address DD:EE:FF:44:55:66 \
  --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
  --fuzz --wordlist payloads.txt --delay_ms 50
```

Example output, single write:

```sh
$ iottack ble write \
    --address DD:EE:FF:44:55:66 \
    --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
    --value R

Plugin name:    ble/write
Execution time: 1.42 s
Status:         pass

[INFO] Write successful to 19b10001-e8f2-537e-4f6c-d104768a1214
  Device:         DD:EE:FF:44:55:66
  Characteristic: 19b10001-e8f2-537e-4f6c-d104768a1214
  Method:         write-with-response
  Bytes written:  1
  Payload (hex):  52
```

## IoTTack Target Bluetooth

The IoTTack Target Bluetooth board advertises a custom LED control service.
Use `iottack ble scan` to find the board's address, then `iottack ble device`
to confirm the characteristic UUID, then use `ble write` to control the LED or
fuzz the characteristic.

| Property | Value |
|----------|-------|
| Device name | `IoTTack Target Bluetooth` |
| Service UUID | `19b10000-e8f2-537e-4f6c-d104768a1214` |
| Characteristic UUID | `19b10001-e8f2-537e-4f6c-d104768a1214` |
| Properties | read, write, write-no-rsp |

Accepted commands:

| Value | Effect |
|-------|--------|
| `R` | Set NeoPixel to red |
| `G` | Set NeoPixel to green |
| `B` | Set NeoPixel to blue |
| `O` | Turn NeoPixel off |

Turn the LED red:

```sh
iottack ble write \
  --address <ADDR> \
  --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
  --value R
```

Cycle through all colors in sequence:

```sh
for cmd in R G B O; do
  iottack ble write \
    --address <ADDR> \
    --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
    --value "$cmd"
done
```

Write the same commands using raw HEX bytes (`R`=`52`, `G`=`47`, `B`=`42`, `O`=`4f`):

```sh
iottack ble write \
  --address <ADDR> \
  --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
  --value 52 --hex
```

Multi-byte hex payloads are also accepted using space, colon, or no separator:

```sh
iottack ble write \
  --address <ADDR> \
  --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
  --value "52 00 00" --hex
```

Fuzz the characteristic to check how the firmware handles unexpected input:

```sh
iottack ble write \
  --address <ADDR> \
  --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
  --fuzz --delay-ms 100
```

The target prints every received write command to its serial output, so connect
a serial monitor to observe how each payload is handled at the firmware level.

Example output, single write to the target:

```sh
$ iottack ble write \
    --address AA:BB:CC:DD:EE:FF \
    --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
    --value G

Plugin name:    ble/write
Execution time: 1.38 s
Status:         pass

[INFO] Write successful to 19b10001-e8f2-537e-4f6c-d104768a1214
  Device:         AA:BB:CC:DD:EE:FF
  Characteristic: 19b10001-e8f2-537e-4f6c-d104768a1214
  Method:         write-with-response
  Bytes written:  1
  Payload (hex):  47
```

Serial output on the target board after receiving the write:

```text
[BLE Write] Raw: 'G'  Parsed: 'G'
[Action Executed] Onboard LED configured to GREEN.
```

Example output, fuzz mode:

```sh
$ iottack ble write \
    --address DD:EE:FF:44:55:66 \
    --characteristic 19b10001-e8f2-537e-4f6c-d104768a1214 \
    --fuzz

Plugin name:    ble/write
Execution time: 38.7 s
Status:         pass

[INFO] No interesting responses
  All payloads x 1 iteration(s) produced no interesting response
  from DD:EE:FF:44:55:66/19b10001-e8f2-537e-4f6c-d104768a1214.
```
