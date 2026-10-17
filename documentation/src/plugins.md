# Plugins

Plugins extend `iottack` with individual test and enumeration capabilities.
Each plugin runs a self-contained check and reports zero or more findings with
a severity level and optional evidence string.

| Plugin | Command | Summary |
|--------|---------|---------|
| [platform](./plugins/platform/platform.md) | `iottack platform` | Host environment report |
| [network - mdns-scan](./plugins/network/mdns-scan.md) | `iottack network mdns-scan` | Discover mDNS/DNS-SD services |
| [uart - baud-scan](./plugins/uart/baud-scan.md) | `iottack uart baud-scan` | Identify active UART baud rate |
| [uart - port-scan](./plugins/uart/port-scan.md) | `iottack uart port-scan` | List serial ports on the host |
| [uart - shell-detect](./plugins/uart/shell-detect.md) | `iottack uart shell-detect` | Detect shell/login prompts on UART |

## Global options

Every plugin accepts these flags in addition to its own arguments:

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Increase log verbosity; repeat for more detail (`-v`, `-vv`, `-vvv`) |
| `--output <FILE>` | `-o` | Save the result to a file |
| `--format <FORMAT>` | `-f` | Output format for `--output`: `text` (default) or `json` |
