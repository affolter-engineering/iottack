# I2C plugins

I2C (Inter-Integrated Circuit) is a two-wire serial bus widely used to connect
sensors, EEPROMs, displays and other peripherals on embedded systems. A single
bus master can address up to 112 devices using 7-bit addresses.

The protocol has no authentication or access control. Any device that can reach
the bus can read sensor values, configuration registers, and stored data, and
write to actuator outputs or configuration registers.

## Hardware requirement

All I2C plugins require an FTDI MPSSE adapter (FT232H, FT2232H, or FT4232H)
connected to the target bus. See [FTDI adapter wiring](../hardware/ftdi.md#i2c)
for pin connections and the required udev rule.

## Plugins

| Plugin | Command | Purpose |
| ------ | ------- | ------- |
| [scan](./scan.md) | `iottack i2c scan` | Probe all 112 valid I2C addresses and report responding devices |
| [read](./read.md) | `iottack i2c read` | Read bytes from a specific device register |

## Severity model

Discovered devices are reported at **Medium** severity. Their presence on the
bus is the finding. Register reads are reported at **Info** since reading a
known address and register is an intentional action rather than a discovery.
