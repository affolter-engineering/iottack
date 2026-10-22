# logic-analyser capture

A logic analyzer passively samples digital signals at a configurable rate and
reports which channels carry active traffic. This is useful for detecting live
debug interfaces (JTAG, SWD, SPI, I2C) on a target device that should have
been disabled before shipping.

## Requirements

A [sigrok](https://sigrok.org/)-supported logic analyzer connected to the host.


Common supported devices include:

- **Demo driver** (`demo`): simulated device, no hardware needed; useful for
  testing the plugin itself.
- **FX2-based analyzers** (`fx2lafw`): cheap 8-channel USB analyzers based on
  the Cypress FX2 chip (clone Salae Logic, USBee, etc.).
- **Saleae Logic** (`saleae-logic`, `saleae-logic16`)
- **Rigol DS1000Z** (`rigol-ds`)
- Any other device supported by libsigrok. Run the plugin without `--driver`
  to discover what is attached.

The `libsigrok` and `libsigrokdecode` system libraries must be installed. On
NixOS the `flake.nix` already pulls them in; on Debian/Ubuntu:

```sh
sudo apt install libsigrok-dev libsigrokdecode-dev
```

It might be required that UDEV rules are present. E.g, for NixOS:

```nix
{
  services.udev = {
    enable = true;
    packages = [ pkgs.libsigrok ];
  };
}
```

## Plugin description

Without `--driver` the plugin initializes a libsigrok context, iterates
every registered driver, and returns one `Info` finding per discovered device
listing its vendor, model, firmware version, serial number, and driver name.

With `--driver` the plugin opens a capture session, sets the requested sample
rate, acquires the requested number of samples, then analyses the raw byte
buffer:

- Each byte represents one sample unit. For ≤ 8 active channels sigrok packs
  one channel per bit, so a non-zero byte means at least one channel was high
  during that sample period.
- The plugin reports one aggregate finding covering all monitored channels,
  then one individual finding per active channel showing its exact activity
  percentage and sample counts. When `--channels` is supplied only those
  channels appear in the per-channel findings; all other bits are ignored.
- Severity scales with the percentage of active samples:

| Active samples | Severity |
| -------------- | -------- |
| < 10 % | Low |
| 10 -49 % | Medium |
| ≥ 50 % | High |

An additional `Medium` finding is raised whenever ≥ 5 % of samples are active,
flagging the possibility of a live debug bus.

## Usage

```sh
# Scan for connected devices
iottack logic-analyser capture

# Capture 1000 samples from the demo driver at 1 MHz (all channels)
iottack logic-analyser capture --driver demo

# Monitor a single channel
iottack logic-analyser capture --driver fx2lafw --channels D0

# Monitor a comma-separated list
iottack logic-analyser capture --driver fx2lafw --channels D0,D2,D4

# Monitor a range (D0 through D3 inclusive)
iottack logic-analyser capture --driver fx2lafw --channels D0-D3

# Mix ranges and individual channels
iottack logic-analyser capture --driver fx2lafw --channels D0-D2,D7

# Capture from an FX2-based analyzer at 4 MHz and save a raw binary dump
iottack logic-analyser capture --driver fx2lafw --samplerate 4000000 --dump-file capture.bin

# Capture 5000 samples, increase verbosity
iottack logic-analyser capture --driver fx2lafw --samples 5000 -v
```

## Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--driver <DRIVER>` | `-d` | *(empty -> scan)* | sigrok driver name (e.g. `demo`, `fx2lafw`). Omit to list connected devices. |
| `--samples <COUNT>` | `-n` | `1000` | Number of samples to capture |
| `--samplerate <HZ>` | `-r` | `1000000` | Sample rate in Hz (1 MHz) |
| `--channels <CHANNELS>` | `-c` | *(all)* | Channels to monitor: `D0`, `D0,D2,D4`, `D0-D3` or mixed `D0-D2,D7`. Omit for all channels. |
| `--dump-file <FILE>` | `-w` | *(none)* | Save a raw binary capture dump to this path |
| `--output <FILE>` | `-o` | - | Save plugin result (findings) to a file |
| `--format <FORMAT>` | `-f` | `text` | Output format: `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Examples

### Scan for devices

```sh
$ iottack logic-analyser capture

Plugin name:    logic-analyser/capture
Execution time: 342 ms
Status:         pass

[INFO] 1 logic analyzer(s) detected
  Pass --driver <DRIVER> with one of the driver names below to start a capture.

[INFO] VENDOR Model (driver: fx2lafw)
  Version: 1.0  Serial: 0001  Connection: 1.42
  Evidence: "vendor=VENDOR, model=Model, version=1.0, serial=0001, connection=1.42, driver=fx2lafw"
```

### Capture with demo driver (no hardware required)

```sh
$ iottack logic-analyser capture --driver demo --samples 200

Plugin name:    logic-analyser/capture
Execution time: 1.21 s
Status:         pass

[HIGH] Signal activity on 8 channel(s): D0, D1, D2, D3, D4, D5, D6, D7
  Monitored: all channels. 200 of 200 samples (100%) showed at least one
  high channel over a 200 µs window at 1000000 Hz. Idle samples: 0.
  Active channels: D0, D1, D2, D3, D4, D5, D6, D7.

[HIGH] D0: 100% active (200/200 samples)
  Channel D0 was high in 200 of 200 samples (100%) over 200 µs at 1000000 Hz.
  Idle samples: 0.

[HIGH] D1: 100% active (200/200 samples)
  Channel D1 was high in 200 of 200 samples (100%) over 200 µs at 1000000 Hz.
  Idle samples: 0.

... (one finding per active channel) ...

[MEDIUM] Sustained bus activity — possible debug interface
  100% of samples were active. Sustained traffic on D0, D1, D2, D3, D4,
  D5, D6, D7 may indicate a live JTAG, SWD, SPI or I2C interface. Confirm
  that debug ports are intentionally exposed and access is properly controlled.
```

### Capture with a channel filter

Only the requested channels appear in the per-channel findings.

```sh
$ iottack logic-analyser capture --driver fx2lafw --channels D0,D2 --samples 500

Plugin name:    logic-analyser/capture
Execution time: 512 ms
Status:         pass

[LOW] Signal activity on 2 channel(s): D0, D2
  Monitored: D0, D2. 45 of 500 samples (9%) showed at least one high
  channel over a 500 µs window at 1000000 Hz. Idle samples: 455.
  Active channels: D0, D2.

[LOW] D0: 8% active (40/500 samples)
  Channel D0 was high in 40 of 500 samples (8%) over 500 µs at 1000000 Hz.
  Idle samples: 460.

[LOW] D2: 1% active (5/500 samples)
  Channel D2 was high in 5 of 500 samples (1%) over 500 µs at 1000000 Hz.
  Idle samples: 495.
```

### All channels idle

```sh
$ iottack logic-analyser capture --driver fx2lafw --samples 1000

Plugin name:    logic-analyser/capture
Execution time: 1.05 s
Status:         pass

[INFO] All channels idle during capture
  Captured 1000 samples (1000 µs at 1000000 Hz) - all monitored channel
  bits were low for the entire window. Monitored: all channels.
```

## Notes

- The `libsigrok-sys` crate and the linked `libsigrok` C library are both
  licensed GPL-3.0-or-later. Review license compatibility if you redistribute
  a build that includes this plugin.
- USB access to logic analyzers typically requires the user to be in the
  `plugdev` group or a matching `udev` rule to be in place. On most Linux
  distributions, install the `sigrok` package to get the udev rules
  automatically.
- The `demo` driver generates a repeating test pattern across all 8 channels.
  All channels will appear active, which is expected.
- For protocol-level decoding (SPI, I2C, JTAG) use the `--dump-file` flag to
  save a capture and then process it with `sigrok-cli --protocol-decoder`.
