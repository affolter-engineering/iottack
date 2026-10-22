# platform

Collects and reports information about the host running `iottack`:

- Framework version
- OS name, version, and codename (from `/etc/os-release`)
- Kernel release (from `/proc/sys/kernel/osrelease`)
- CPU architecture
- Effective user ID - flags whether the process has root privileges
- Available serial ports (`/dev/ttyUSB*`, `/dev/ttyACM*`, etc.)
- USB-serial devices enumerated via sysfs, including vendor/product details
- 
## Usage

```sh
iottack platform [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Example

```sh
$ iottack platform

Plugin name:    platform/platform
Execution time: 3ms
Status:         pass
Date:           2026-10-17 00:00:00 UTC

Host environment
  iottack release: 0.2.6
  OS: NixOS 26.11 (zokor)
  Kernel: 6.18.54
  Architecture: x86_64

Running as unprivileged user (euid=1000)
  Some serial ports or USB devices may require elevated privileges.
  Run with sudo if access is denied.

Serial ports available (1)
  /dev/ttyUSB0

USB-serial device: /dev/ttyUSB0
  0403:6001 | FT232 USB-Serial (FTDI) | sysfs: /sys/devices/...
```
