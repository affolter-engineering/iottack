# modbus write-coil

Writes a boolean value to a single Modbus coil using function code 05 (Write
Single Coil).

Coils typically control digital outputs : relays, solenoid valves, motor
starters, indicator lights and similar actuators. Unauthenticated coil writes
can directly affect physical processes.

**Warning:** Writing to coils can immediately actuate physical devices!

## Status

| Result | Meaning |
|--------|---------|
| `pass` | Write accepted by the device |
| `fail` | Write rejected, invalid value, or connection failed |

## Severity classification

| Severity | Condition |
|----------|-----------|
| Critical | Write succeeded (unauthenticated control of a digital output) |
| Info | Write failed, invalid value, or connection failed |

## Usage

```sh
iottack modbus write-coil --host <HOST> --value <VALUE> [OPTIONS]
iottack modbus write-coil --serial <DEVICE> --value <VALUE> [OPTIONS]
```

`--value` is required.

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required or --serial)* | Target hostname or IP for Modbus/TCP |
| `--tcp-port <PORT>` | - | `502` | Modbus/TCP port |
| `--serial <DEVICE>` | `-s` | *(required or --host)* | Serial device for Modbus RTU (e.g., `/dev/ttyUSB0`) |
| `--baud <BAUD>` | - | `9600` | Baud rate for RTU serial |
| `--unit <ID>` | `-u` | `1` | Modbus unit/slave ID (1-247) |
| `--timeout-ms <MS>` | `-t` | `3000` | Timeout in milliseconds |
| `--address <ADDR>` | `-a` | `0` | Coil address (0-65535) |
| `--value <VALUE>` | `-v` | *(required)* | Coil state: `on`/`off`, `1`/`0` or `true`/`false` |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

### Accepted values for `--value`

| Input | Meaning |
|-------|---------|
| `on`, `1`, `true`, `yes` | Coil ON (0xFF00 on the wire) |
| `off`, `0`, `false`, `no` | Coil OFF (0x0000 on the wire) |

## Examples

Turn coil 5 on:

```sh
iottack modbus write-coil --host 192.168.1.100 --address 5 --value on
```

Turn coil 5 off:

```sh
iottack modbus write-coil --host 192.168.1.100 --address 5 --value off
```

Write over RTU serial, unit 2:

```sh
iottack modbus write-coil --serial /dev/ttyUSB0 --unit 2 \
  --address 0 --value 1
```

## Example output

```text
Plugin name:    modbus/write-coil
Execution time: 0.06 s
Status:         pass

[CRITICAL] Modbus/TCP: coil 5 set to ON without authentication (FC05)
  Unit 1: coil at address 5 written to ON.
  This may directly affect a physical actuator or digital output.
  Evidence: "address=5 value=ON"
```
