# can enumerate

Active and passive device discovery across three sequential phases: passive
traffic observation, OBD-II ECU discovery and CANopen node guarding with
device type identification.

## Status

| Result | Meaning |
| ------ | ------- |
| `pass` | All configured phases completed |
| `fail` | Interface could not be opened |

## Severity classification

| Severity | Condition |
| -------- | --------- |
| High | OBD-II ECU responded with supported PID list |
| High | CANopen node found and device type identified via SDO |
| Medium | CANopen node found (heartbeat or node guarding) but no SDO response |
| Info | No devices found in a phase, or phase skipped |

## Usage

```sh
iottack can enumerate [OPTIONS]
```

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--iface <IFACE>` | `-i` | `can0` | SocketCAN interface name |
| `--passive-ms <MS>` | - | `1000` | Duration of the passive listening phase in ms |
| `--probe-ms <MS>` | - | `500` | Response collection window after each active probe phase |
| `--no-canopen` | - | off | Skip the CANopen node guarding and SDO phase |
| `--no-obdii` | - | off | Skip the OBD-II ECU discovery phase |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Discovery phases

### Phase 1 - Passive (default 1 s)

Listens for spontaneous traffic without transmitting anything. CANopen nodes
periodically broadcast heartbeat frames on `0x700 + NodeID`. Nodes found this
way require no probe and cause no bus disruption.

### Phase 2 - OBD-II ECU discovery

Transmits a single Service 01 PID 00 functional broadcast to `0x7DF`:

```text
ID: 0x7DF  data: [02 01 00]
  02 = 2 additional bytes
  01 = Service 01 (current powertrain data)
  00 = PID 00 (supported PIDs 01–20 bitmask)
```

Any ECU that supports OBD-II responds on `0x7E8-0x7EF` with a bitmask of
the PIDs it supports. Each responding address is reported as a separate High
severity finding. The ECU index is `response_id - 0x7E8`.

### Phase 3 - CANopen node guarding

Transmits RTR (Remote Transmission Request) frames simultaneously to
`0x700 + N` for N = 1 through 127. A node that supports node guarding
responds with a data frame containing its current NMT state.

All 127 probes are sent before the response window opens, so the total
active probe time is one `--probe-ms` window rather than 127 individual
timeouts.

After collecting node guard responses, an SDO upload initiate request is
sent to each found node to read **object 0x1000 sub-index 0 (Device Type)**:

```text
ID: 0x600 + NodeID  data: [40 00 10 00 00 00 00 00]
  40 = initiate upload
  00 10 = object index 0x1000
  00 = sub-index 0
```

The 32-bit response value encodes the CANopen device profile in the lower
16 bits. Nodes that respond are reported at High severity with the decoded
profile. Nodes that do not support SDO or do not respond within `--probe-ms`
are reported at Medium.

## CANopen NMT states

| State byte | Meaning |
|------------|---------|
| `0x00` | Boot-up / Initialising |
| `0x04` | Stopped |
| `0x05` | Operational |
| `0x7F` | Pre-Operational |

## CANopen device profiles (object 0x1000)

| Profile (lower 16 bits) | Device type |
| ----------------------- | ----------- |
| 0x0191 | Encoder |
| 0x0192 | Stepper motor |
| 0x0401 | AC drive (IEC 61800-7-201) |
| 0x0402 | Stepper motor drive |
| 0x0403 | AC servo drive |
| 0x0404 | Digital I/O module |
| 0x0405 | Analog I/O module |
| 0x0406 | Encoder interface |
| 0x0407 | Safety controller |
| 0xFFFF | Generic CANopen device |

## Examples

Full scan with all phases:

```sh
iottack can enumerate
```

OBD-II only with a longer response window:

```sh
iottack can enumerate --no-canopen --probe-ms 1000
```

CANopen only on a custom interface:

```sh
iottack can enumerate --no-obdii --iface vcan0
```

Extend the passive window for slow heartbeat cycles (e.g., 1 Hz nodes):

```sh
iottack can enumerate --passive-ms 3000
```

## Example output

```text
Plugin name:    can/enumerate
Execution time: 2.01 s
Status:         pass

[MEDIUM] 2 CANopen node(s) discovered via passive heartbeat on can0
    Node   1  ID=701h  state=Operational
    Node   2  ID=702h  state=Operational

[HIGH] OBD-II ECU 0 at 0x7E8h: 13 supported PID(s)
  ECU index 0 (request 0x7E0h → response 0x7E8h)
  Supported PIDs (01-20): 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0C,
                           0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x13
  Raw response: [06 41 00 BE 1F A8 13]

[HIGH] CANopen node 1 at 701h: Operational
  Node ID  : 1
  Heartbeat: 701h
  State    : Operational (0x05)
  Device   : profile=0x0404 (Digital I/O module)  raw=0x00000404

[HIGH] CANopen node 2 at 702h: Operational
  Node ID  : 2
  Heartbeat: 702h
  State    : Operational (0x05)
  Device   : device type unknown (SDO timeout or not supported)
```

## Notes

- Node guarding is a legacy CANopen mechanism. Modern deployments often use
  heartbeat messages instead. If RTR probes produce no response, nodes may
  still be detectable via the passive heartbeat phase.
- Sending the OBD-II functional broadcast (`0x7DF`) is a standard diagnostic
  operation and is safe on any compliant OBD-II bus.
- The CANopen NMT reset command (`0x000`, data `0x81 0x00`) is **not** sent by
  this plugin. Discovery is non-destructive.
