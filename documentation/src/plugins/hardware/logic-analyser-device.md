# logic-analyser device

List all sigrok-supported logic analyzers currently connected to the host,
together with their full details: vendor, model, firmware version, serial
number, connection ID, driver name, and the complete channel list.

## Requirements

Same as [`logic-analyser capture`](./logic-analyser.md#requirements) — the
`libsigrok` system library must be installed and the user must have access to
USB/serial devices.

## Plugin description

The plugin initialises a libsigrok context, iterates every registered driver,
and returns one `Info` finding per discovered device. Each finding includes:

- Vendor, model, firmware version
- Serial number and connection ID
- Driver short name and long name
- Number of channels and their names (disabled channels are marked)

No hardware interaction beyond device scanning takes place; the device is not
opened and no samples are captured.

## Usage

```sh
iottack logic-analyser device
```

## Example output

### One device found

```sh
$ iottack logic-analyser device

Plugin name:    logic-analyser/device
Execution time: 284 ms
Status:         pass

[INFO] 1 logic analyzer(s) detected
  Use 'iottack logic-analyser capture --driver <DRIVER>' to start a capture.

[INFO] ACME Logic Pro (driver: fx2lafw)
  Driver:     fx2lafw (Cypress FX2 USB hardware logic analyzer)
  Vendor:     ACME
  Model:      Logic Pro
  Version:    1.02
  Serial:     00A1B2C3
  Connection: 1.7
  Channels:   8 — D0, D1, D2, D3, D4, D5, D6, D7
```

### No devices found

```sh
$ iottack logic-analyser device

Plugin name:    logic-analyser/device
Execution time: 112 ms
Status:         pass

[INFO] No sigrok-supported logic analyzers found
  No devices were detected. Connect a supported logic analyzer and retry,
  or use 'iottack logic-analyser capture --driver demo' to test with a
  simulated device.
```

## Notes

- The `demo` driver always appears because it requires no hardware. Use
  `iottack logic-analyser capture --driver demo` to test the capture plugin
  without a physical device.
- Disabled channels are listed with a `(disabled)` suffix. A channel may be
  disabled if the device was previously configured and the driver preserved
  that state.
- To capture samples from a listed device pass its driver name to
  `iottack logic-analyser capture --driver <DRIVER>`.
