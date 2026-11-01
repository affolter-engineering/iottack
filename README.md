# iottack

A Rust-based framework for testing and debugging common IoT protocols and IoT implementations
which are used by that hardware, those products and infrastructures.

Check the [Plugin overview](https://affolter-engineering.github.io/iottack/plugins.html)

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
