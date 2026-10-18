# iottack

A Rust-based framework for testing common IoT protocols and IoT implementations which are used by that hardware, those
products and infrastructures. Plugins provide support for:

| Plugin | Command | Description |
| --- | --- | --- |
| `platform/platform` | `iottack platform` | Host environment, USB devices and specialized hardware |
| `network/mdns-scan` | `iottack network mdns-scan` | Discover mDNS/DNS-SD services on the local network |
| `network/telnet` | `iottack telnet` | Connect to a Telnet service and detect banners, login prompts, and default credentials |
| `uart/baud-scan` | `iottack uart baud-scan` | Probe common UART baud rates to identify the active configuration |
| `uart/fuzz` | `iottack uart fuzz` | Send malformed and custom payloads to a UART interface and report anomalous responses |
| `uart/port-scan` | `iottack uart port-scan` | Discover serial ports available on this host |
| `uart/shell-detect` | `iottack uart shell-detect` | Detect interactive shell or login prompt on a UART interface |
| `uart/terminal` | `iottack uart terminal` | Open an interactive terminal session over a UART interface |

## Build

```sh
cargo build --release
```

With Nix:

```sh
nix build
nix run . -- platform
```

## Usage

### PLatform details

Collect platform environment details about the host which acts as the test platform:

```sh
iottack platform
```

Reports operating system, kernel/architecture and privilege level.

### List available plugins

```sh
iottack list
```

## Development shell (Nix)

```sh
nix develop
cargo build
cargo test
```

## Adding a new protocol

1. Create `src/protocols/<name>/` with a config struct, a session struct and a `<Name>Plugin` trait that extends `Plugin`.
2. Implement one or more concrete plugin structs.
3. Export the module from `src/protocols/mod.rs`.
4. Register the plugins in `build_registry()` in `src/bin/main.rs`.

## Author(s)

- Fabian Affolter (@fabaff)

## License

MIT
