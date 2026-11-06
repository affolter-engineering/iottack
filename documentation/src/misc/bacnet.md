# BACnet/IP Simulator

The BACnet/IP simulator is a standalone Python server that emulates a realistic
building automation controller with two virtual stations pre-populated with
sensor and actuator objects. It runs entirely in software. No physical hardware
required. So every `iottack bacnet` plugin can be exercised locally.

Source: [`test-targets/iottack-target-bacnet/simulator.py`](../../../test-targets/iottack-target-bacnet/simulator.py)

## Requirements

[bacpypes3](https://github.com/JoelBender/BACpypes3). The Nix flake in
`test-targets/iottack-target-bacnet/` provides a reproducible environment with the
correct version pinned.

## Device layout

**Device instance:**: 100 (configurable via `--device`)
**Device name:**: SimBAS
**Protocol:**: BACnet/IP, UDP port 47808 (configurable via `--port`)

### Station 1 - Boiler Room Controller

| Object type | Instance | Name | Value | Units |
| ----------- | -------- | ---- | ----- | ----- |
| analogInput | 1 | boiler-temp | 75.3 | °C |
| analogInput | 2 | water-pressure | 2.1 | bar |
| analogInput | 3 | flue-gas-temp | 185.0 | °C |
| analogOutput | 1 | burner-power | 65.0 | % |
| analogOutput | 2 | pump-speed | 80.0 | % |
| binaryInput | 1 | high-temp-alarm | inactive | - |
| binaryInput | 2 | low-pressure-alarm | inactive | - |
| binaryOutput | 1 | pump-enable | active | - |
| binaryOutput | 2 | burner-enable | active | - |

### Station 2 - HVAC Unit

| Object type | Instance | Name | Value | Units |
| ----------- | -------- | ---- | ----- | ----- |
| analogInput | 11 | supply-air-temp | 18.5 | °C |
| analogInput | 12 | return-air-temp | 24.2 | °C |
| analogInput | 13 | outdoor-air-temp | 9.8 | °C |
| analogOutput | 11 | cooling-setpoint | 21.0 | °C |
| analogOutput | 12 | heating-setpoint | 19.0 | °C |
| analogOutput | 13 | fan-speed | 75.0 | % |
| binaryInput | 11 | fan-running | active | - |
| binaryInput | 12 | filter-dirty | inactive | - |
| binaryOutput | 11 | chilled-water-valve | active | - |
| binaryOutput | 12 | hot-water-valve | inactive | - |

## Usage

### With Nix (recommended)

```sh
# Start on 0.0.0.0:47808, device instance 100
nix run ./test-targets/iottack-target-bacnet

# Loopback only
nix run ./test-targets/iottack-target-bacnet -- --host 127.0.0.1

# Custom port and device instance
nix run ./test-targets/iottack-target-bacnet -- --port 47809 --device 200
```

### Without Nix

```sh
pip install bacpypes3
python test-targets/iottack-target-bacnet/simulator.py
python test-targets/iottack-target-bacnet/simulator.py --host 127.0.0.1 --port 47808 --device 100
```

## CLI options

| Option | Default | Description |
| ------ | ------- | ----------- |
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `47808` | UDP port |
| `--device` | `100` | BACnet device instance number |

## Code

```python
{{#include ../../../test-targets/iottack-target-bacnet/simulator.py}}
```
