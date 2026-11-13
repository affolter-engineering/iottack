# CAN Bus Simulator

The CAN bus simulator is a standalone Rust binary that emulates a mixed
industrial/automotive CAN network. It transmits a continuous stream of
realistic frames over a Linux SocketCAN interface so that every `iottack can`
plugin can be exercised locally without physical hardware.

Source: [`test-targets/iottack-target-can/src/main.rs`](../../../test-targets/iottack-target-can/src/main.rs)

## Requirements

- Linux with the `vcan` kernel module (`modprobe vcan`)
- Rust toolchain (provided by the Nix flake in `test-targets/iottack-target-can/`)

## Node layout

The simulator brings up 14 virtual nodes across three higher-layer protocols.

### CANopen master

| Node | CAN ID | Format | Period | Notes |
| ---- | ------ | ------ | ------ | ----- |
| `canopen-sync` | 0x080 | SFF | 100 ms | SYNC object |
| `canopen-emcy-node1` | 0x081 | SFF | 5 s | EMCY from node 1 (generic error / fault cleared) |

### CANopen node 1 — temperature/pressure sensor

| Node | CAN ID | Format | Period | Notes |
| ---- | ------ | ------ | ------ | ----- |
| `canopen-node1-tpdo1` | 0x181 | SFF | 100 ms | Temperature + pressure (PDO) |
| `canopen-node1-tpdo2` | 0x281 | SFF | 200 ms | Digital I/O status (PDO) |
| `canopen-node1-sdo-resp` | 0x581 | SFF | 2 s | SDO server response (device type, vendor ID) |
| `canopen-node1-sdo-req` | 0x601 | SFF | 2 s | SDO client request — includes unauthenticated write to digital outputs |
| `canopen-node1-heartbeat` | 0x701 | SFF | 1 s | NMT heartbeat (operational / pre-operational) |

### CANopen node 2 — motor controller

| Node | CAN ID | Format | Period | Notes |
| ---- | ------ | ------ | ------ | ----- |
| `canopen-node2-tpdo1` | 0x182 | SFF | 200 ms | Motor RPM (PDO) |
| `canopen-node2-heartbeat` | 0x702 | SFF | 1 s | NMT heartbeat |

### CANopen node 3 — valve controller

| Node | CAN ID | Format | Period | Notes |
| ---- | ------ | ------ | ------ | ----- |
| `canopen-node3-tpdo1` | 0x183 | SFF | 500 ms | Valve setpoint + actual position (PDO) |
| `canopen-node3-heartbeat` | 0x703 | SFF | 1 s | NMT heartbeat |

### OBD-II / ISO 15765-4

| Node | CAN ID | Format | Period | Notes |
| ---- | ------ | ------ | ------ | ----- |
| `obd2-broadcast` | 0x7DF | SFF | 1 s | Diagnostic broadcast — HIGH severity |
| `obd2-ecu1-response` | 0x7E8 | SFF | 1 s | ECU 1 response (RPM, speed, coolant temp, intake air) — HIGH severity |

### J1939 (extended 29-bit)

| Node | CAN ID | Format | Period | Notes |
| ---- | ------ | ------ | ------ | ----- |
| `j1939-eec1` | 0x0CF00400 | EFF | 100 ms | PGN 0xF004 EEC1 — torque demand + engine speed |

## CLI options

| Option | Default | Description |
| ------ | ------- | ----------- |
| `-i`, `--iface` | `vcan0` | SocketCAN interface to transmit on |
| `-d`, `--duration` | `0` | Stop after N seconds; `0` runs until Ctrl-C |
| `--stats-interval` | `5` | Print frame rate statistics every N seconds |

## Setup

A virtual CAN interface must be up before starting the simulator:

```sh
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set vcan0 up
```

## Usage

### With Nix (recommended)

```sh
# Start on vcan0, run indefinitely
nix run ./test-targets/iottack-target-can

# Custom interface
nix run ./test-targets/iottack-target-can -- --iface vcan1

# Stop after 30 seconds
nix run ./test-targets/iottack-target-can -- --duration 30
```

### Without Nix

```sh
cd test-targets/iottack-target-can
cargo run -- --iface vcan0
cargo run -- --iface vcan0 --duration 30
```

## Testing with iottack

With the simulator running, open a second terminal and run any CAN plugin:

```sh
iottack can scan     --iface vcan0
iottack can dump     --iface vcan0 --duration 5
iottack can enumerate --iface vcan0
```

Expected findings from `can scan` and `can enumerate`:

- **High**: OBD-II diagnostic IDs observed (0x7DF, 0x7E8)
- **High**: CANopen nodes identified via SDO (node 1 device type)
- **Medium**: CANopen heartbeat nodes (nodes 1-3)
- **Medium**: CANopen SDO, PDO, NMT IDs observed

## Code

```rust
{{#include ../../../test-targets/iottack-target-can/src/main.rs}}
```
