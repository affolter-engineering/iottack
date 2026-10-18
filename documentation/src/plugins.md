# Plugins

Plugins extend `iottack` with individual test and enumeration capabilities.
Each plugin runs a self-contained check and reports zero or more findings with
a severity level and optional evidence string.

| Plugin | Command | Summary |
|--------|---------|---------|
| [platform](./plugins/platform/platform.md) | `iottack platform` | Report details about the host/platform environment |
| [http - banner](./plugins/http/http-banner.md) | `iottack http banner` | Checks HTTP banner and common settings |
| [network - mdns-scan](./plugins/network/mdns-scan.md) | `iottack network mdns-scan` | Discover mDNS/DNS-SD services on the local network |
| [network - telnet](./plugins/network/telnet.md) | `iottack telnet` | Connect to a Telnet service and detect banners, login prompts and default credentials |
| [uart - baud-scan](./plugins/uart/baud-scan.md) | `iottack uart baud-scan` | Probe common UART baud rates to identify the active configuration |
| [uart - port-scan](./plugins/uart/port-scan.md) | `iottack uart port-scan` | Discover serial ports available on this host |
| [uart - fuzz](./plugins/uart/fuzz.md) | `iottack uart fuzz` | Send malformed and custom payloads to a UART interface and report anomalous responses |
| [uart - shell-detect](./plugins/uart/shell-detect.md) | `iottack uart shell-detect` | Detect interactive shell or login prompt on a UART interface |

## Global options

Every plugin accepts these flags in addition to its own arguments:

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Increase log verbosity; repeat for more detail (`-v`, `-vv`, `-vvv`) |
| `--output <FILE>` | `-o` | Save the result to a file |
| `--format <FORMAT>` | `-f` | Output format for `--output`: `text` (default) or `json` |
