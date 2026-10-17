# iottack

A Rust-based framework for testing common IoT protocols and IoT implementations which are used by that hardware, those
products and infrastructures. Plugins provide support for:

| Plugin | Command | Description |
| --- | --- | --- |
| `platform/platform` | `iottack platform` | Host environment, USB devices and specialized hardware |
| `network/mdns-scan` | `iottack network mdns-scan` | Discover mDNS/DNS-SD services on the local network |
| `uart/baud-scan` | `iottack uart baud-scan` | Probe common UART baud rates to identify the active configuration |
| `uart/port-scan` | `iottack uart port-scan` | Discover serial ports available on this host |
| `uart/shell-detect` | `iottack uart shell-detect` | Detect interactive shell or login prompt on a UART interface |



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
4. Add `inventory::submit! { crate::PluginFactory(|| Box::new(MyPlugin::new()) as Box<dyn crate::Plugin>) }` at the bottom of each plugin file — no changes to `main.rs` needed.

## Author(s)

- Fabian Affolter (@fabaff)

## License

MIT
