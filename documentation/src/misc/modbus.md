# Modbus/TCP Simulator

The Modbus/TCP simulator is a standalone Python server that emulates a realistic
PLC with pre-populated data across all four Modbus data types. It runs entirely
in software — no physical hardware required. So every `iottack modbus` plugin
can be exercised locally.

Source: [`test-targets/iottack-modbus/simulator.py`](../../../test-targets/iottack-modbus/simulator.py)

## Requirements

[pymodbus](https://github.com/pymodbus-dev/pymodbus) 3.x. The Nix flake in
`test-targets/iottack-modbus/` provides a reproducible environment with the
correct version pinned.

## Data layout

| Data type | Function code | Address range | Count | Notes |
|-----------|--------------|---------------|-------|-------|
| Holding registers | FC03 | 0-999 | 1000 | Status, setpoints, counters, config, alarm thresholds |
| Input registers | FC04 | 0-99 | 100 | Temperature, pressure, voltage, current, uptime |
| Coils | FC01 | 0-31 | 32 | Alternating ON/OFF pattern |
| Discrete inputs | FC02 | 0-31 | 32 | Fixed sensor bits (door open, motor running, ...) |

FC43 MEI device identification (Read Device Identification) is also enabled with
vendor strings: `iottack Labs / SIMBUS-1000 / 1.0.0`.

## Usage

### With Nix (recommended)

```sh
# Start on 0.0.0.0:5020, unit 1
nix run ./test-targets/iottack-modbus

# Loopback only
nix run ./test-targets/iottack-modbus -- --host 127.0.0.1

# Custom port and unit ID
nix run ./test-targets/iottack-modbus -- --port 502 --unit 3
```

### Without Nix

```sh
pip install pymodbus
python test-targets/iottack-modbus/simulator.py
python test-targets/iottack-modbus/simulator.py --host 127.0.0.1 --port 5020 --unit 1
```

## Testing with iottack

Start the simulator first, then run any of the commands below against it.

### Device identification

```sh
iottack modbus device-info --host 127.0.0.1 --tcp-port 5020
```

### Read holding registers

```sh
iottack modbus read-registers --host 127.0.0.1 --tcp-port 5020 --address 0 --count 10
```

Read input registers (FC04):

```sh
iottack modbus read-registers --host 127.0.0.1 --tcp-port 5020 \
    --register-type input --address 0 --count 10
```

### Read coils

```sh
iottack modbus read-coils --host 127.0.0.1 --tcp-port 5020 --address 0 --count 32
```

Read discrete inputs (FC02):

```sh
iottack modbus read-coils --host 127.0.0.1 --tcp-port 5020 \
    --coil-type discrete --address 0 --count 32
```

### Write a coil

```sh
iottack modbus write-coil --host 127.0.0.1 --tcp-port 5020 --address 0 --value on
```

### Write a register

Single register (FC06):

```sh
iottack modbus write-register --host 127.0.0.1 --tcp-port 5020 --address 1 --value 0x00FF
```

Multiple registers (FC16):

```sh
iottack modbus write-register --host 127.0.0.1 --tcp-port 5020 \
    --address 200 --values 0x0001,0x09C4,0x0003
```

## CLI options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `5020` | TCP port |
| `--unit` | `1` | Modbus unit/slave ID |

## Code

```python
{{#include ../../../test-targets/iottack-modbus/simulator.py}}
```
