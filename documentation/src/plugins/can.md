# CAN bus plugins

CAN (Controller Area Network) is a robust serial bus protocol developed by Bosch
in 1986. It is the dominant communication standard in automotive electronics and
is widely deployed in industrial automation, medical devices, aerospace systems
and building controls.

The protocol was designed for reliability in electrically noisy environments. It
has no built-in authentication, encryption, or access control. Any node connected
to the bus can read all traffic and inject arbitrary frames without restriction.

## Frame formats

CAN supports two frame formats distinguished by the identifier length:

| Format | ID bits | Range | Common use |
| ------ | ------- | ----- | ---------- |
| SFF (Standard Frame Format) | 11 bits | 0x000-0x7FF | CANopen, OBD-II |
| EFF (Extended Frame Format) | 29 bits | 0x00000000-0x1FFFFFFF | J1939, proprietary |

## Common higher-layer protocols

| Protocol | ID range | Domain |
| -------- | -------- | ------ |
| CANopen | 0x001-0x77F (SFF) | Industrial automation, medical |
| OBD-II (ISO 15765-4) | 0x7DF, 0x7E0-0x7EF (SFF) | Automotive diagnostics |
| J1939 | EFF, PGN-encoded | Heavy vehicles (trucks, buses) |
| CANaerospace | SFF | Avionics |

## Setup

All CAN plugins require a Linux SocketCAN interface. Bring one up before running
any plugin. Make `can-utils` available on your system.

**USB CAN adapters using the `gs_usb` kernel module** (CANable, CANtact, PEAK
PCAN-USB in GS-USB mode):

```sh
sudo ip link set can0 up type can bitrate 500000
```

**SLCAN-based adapters** (older USB-to-CAN bridges):

```sh
sudo slcand -o -c -s6 /dev/ttyACM0 can0
sudo ip link set can0 up
```

**Virtual CAN** (for local testing or replay):

```sh
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set vcan0 up
```

To verify the interface is up:

```sh
ip link show type can
18: can0: <NOARP,UP,LOWER_UP> mtu 16 qdisc pfifo_fast state UP mode DEFAULT group default qlen 10
    link/can
```

## Plugins

| Plugin | Command | Mode |
| ------ | ------- | ---- |
| [dump](./can/dump.md) | `iottack can dump` | Passive capture and traffic analysis |
| [scan](./can/scan.md) | `iottack can scan` | Passive ID enumeration |
| [send](./can/send.md) | `iottack can send` | Active: transmit arbitrary frames |
| [enumerate](./can/enumerate.md) | `iottack can enumerate` | Active device discovery (OBD-II & CANopen) |

## Severity model

| Severity | Condition |
| -------- | --------- |
| High | OBD-II diagnostic IDs observed or responding (0x7DF, 0x7E0-0x7EF) |
| High | CANopen node found and device type identified via SDO |
| Medium | CANopen node found (heartbeat or node guarding) |
| Medium | CANopen SDO, PDO, or NMT management IDs observed |
| Low | CAN error frames detected |
| Info | General traffic statistics, no active traffic, or interface error |
