# Plugins

Plugins extend `iottack` with individual test and enumeration capabilities.
Each plugin runs a self-contained check and reports zero or more findings with
a severity level and optional evidence string.

| Plugin | Command | Summary |
|--------|---------|---------|
| [amqp scan](./plugins/amqp/amqp-scan.md) | `iottack amqp scan` | Detect an AMQP broker and test for default credentials |
| [ble adapter](./plugins/ble/ble-adapter.md) | `iottack ble adapter` | List Bluetooth adapters and report their power and discoverability state |
| [ble device](./plugins/ble/ble-device.md) | `iottack ble device --address <ADDR>` | Enumerate GATT services and characteristics of a single BLE device |
| [ble scan](./plugins/ble/ble-scan.md) | `iottack ble scan` | Discover nearby Bluetooth Low Energy devices and report their properties |
| [ble write](./plugins/ble/ble-write.md) | `iottack ble write --address <ADDR> --characteristic <UUID>` | Write a value to a BLE GATT characteristic or fuzz it |
| [http banner](./plugins/http/http-banner.md) | `iottack http banner` | Checks HTTP banner and common settings |
<<<<<<< Updated upstream
| [modbus device-info](./plugins/modbus/device-info.md) | `iottack modbus device-info` | Read Modbus controller device identification (FC43 MEI) |
| [modbus read-coils](./plugins/modbus/read-coils.md) | `iottack modbus read-coils` | Read Modbus coils or discrete inputs |
| [modbus read-registers](./plugins/modbus/read-registers.md) | `iottack modbus read-registers` | Read Modbus holding or input registers |
| [modbus write-coil](./plugins/modbus/write-coil.md) | `iottack modbus write-coil` | Write a single Modbus coil (FC05) |
| [modbus write-register](./plugins/modbus/write-register.md) | `iottack modbus write-register` | Write a value to one or more Modbus holding registers |
=======
| [ftdi device](./plugins/hardware/ftdi-device.md) | `iottack ftdi device` | Enumerate FTDI USB adapters and report chip type, chip ID, EEPROM strings and MPSSE capability |
| [i2c scan](./plugins/i2c/scan.md) | `iottack i2c scan` | Probe all valid 7-bit I2C addresses via an FTDI MPSSE adapter |
| [i2c read](./plugins/i2c/read.md) | `iottack i2c read --address <HEX>` | Read bytes from an I2C device register via an FTDI MPSSE adapter |
>>>>>>> Stashed changes
| [mqtt](./plugins/mqtt.md) | `iottack mqtt` | Work with MQTT |
| [network mdns-scan](./plugins/network/mdns-scan.md) | `iottack network mdns-scan` | Discover mDNS/DNS-SD services on the local network |
| [network telnet](./plugins/network/telnet.md) | `iottack network telnet` | Connect to a Telnet service and detect banners, login prompts and default credentials |
| [tcp banner](./plugins/tcp/banner.md) | `iottack tcp banner` | Connect to a TCP service and capture the initial banner, identifying the protocol and flagging cleartext services |
| [tcp fuzz](./plugins/tcp/fuzz.md) | `iottack tcp fuzz` | Send malformed and custom payloads to a TCP service and report anomalous responses |
| [tcp shell-detect](./plugins/tcp/shell-detect.md) | `iottack tcp shell-detect` | Detect interactive shell or login prompt on a TCP service |
| [platform](./plugins/platform/platform.md) | `iottack platform` | Report details about the host/platform environment |
| [uart baud-scan](./plugins/uart/baud-scan.md) | `iottack uart baud-scan` | Probe common UART baud rates to identify the active configuration |
| [uart fuzz](./plugins/uart/fuzz.md) | `iottack uart fuzz` | Send malformed and custom payloads to a UART interface and report anomalous responses |
| [uart port-scan](./plugins/uart/port-scan.md) | `iottack uart port-scan` | Discover serial ports available on this host |
| [uart shell-detect](./plugins/uart/shell-detect.md) | `iottack uart shell-detect` | Detect interactive shell or login prompt on a UART interface |
| [uart terminal](./plugins/uart/terminal.md) | `iottack uart terminal` | Open an interactive terminal session over a UART interface |
| [vulns bluefi](./plugins/vulnerabilitites/bluefi.md) | `iottack vuln bluefi` | Check ESP for CVE-2025-27840 |

## Global options

Every plugin accepts these flags in addition to its own arguments:

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Increase log verbosity; repeat for more detail (`-v`, `-vv`, `-vvv`) |
| `--output <FILE>` | `-o` | Save the result to a file |
| `--format <FORMAT>` | `-f` | Output format for `--output`: `text` (default) or `json` |
