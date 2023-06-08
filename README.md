# iottack

A Rust-based framework for testing common IoT protocols and IoT implementations which are used by that hardware, those
products and infrastructures. Plugins provide support for .

## Supported plugins

| Plugin | Command | Description |
| --- | --- | --- |
| `platform/details` | `details` | Host environment, USB devices and specialized hardware |

## Build

```sh
cargo build --release
```

With Nix:

```sh
nix build
nix run . -- disclose
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
