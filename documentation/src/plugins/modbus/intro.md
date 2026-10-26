# Modbus plugins

Modbus is a serial communication protocol originally developed for industrial
programmable logic controllers (PLCs). It has become the de-facto standard for
industrial automation and is widely deployed in PLCs, HMIs, energy meters,
building management systems and other OT/ICS equipment.

The protocol has no built-in authentication or encryption. Any device that can
reach TCP port 502 or the correct serial bus, can read sensor values,
setpoints, and configuration data and write directly to outputs or actuators.

## Transport modes

All plugins support two transport modes selected by exclusive flags:

| Mode | Flag | Default port/baud |
|------|------|-------------------|
| TCP | `--host <IP>` | `502` |
| RTU serial | `--serial <DEVICE>` | `9600` baud |

Exactly one of `--host` or `--serial` must be supplied. TCP is tried when
`--host` is set. RTU is used when `--serial` is set.

## Plugins

| Plugin | Command | Function code(s) |
|--------|---------|-----------------|
| [device-info](./device-info.md) | `modbus device-info` | FC03 (probe) & FC43 MEI |
| [enumerate](./enumerate.md) | `modbus enumerate` | FC01, FC02, FC03, FC04 |
| [read-registers](./read-registers.md) | `modbus read-registers` | FC03/FC04 |
| [write-register](./write-register.md) | `modbus write-register` | FC06/FC16 |
| [read-coils](./read-coils.md) | `modbus read-coils` | FC01/FC02 |
| [write-coil](./write-coil.md) | `modbus write-coil` | FC05 |

## Severity model

Successful unauthenticated **reads** are reported as **High**. The absence of
any access control is the finding, regardless of the data values returned.

Successful unauthenticated **writes** are reported as **Critical** — they
demonstrate the ability to modify process state, setpoints or actuator outputs
without any authentication.

Connection failures and unsupported function codes are reported as **Info**.
