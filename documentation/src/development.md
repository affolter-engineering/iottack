# Development

## Adding a new plugin

Plugins are the unit of work in `iottack`. Each plugin performs one focused test
and reports zero or more findings with a severity level and optional evidence
string. Adding a plugin requires no changes to `main.rs` or any central
registry. The framework discovers plugins automatically at startup.

A complete working reference lives at
`src/protocols/example/example.rs`. The walkthrough below follows that file
step by step.

### 1. Create the module files

Plugins are grouped by under `src/protocols/`, `src/hardware` (if it's a physical
device like a Logic analyzer) or `src/vulns`. Create a directory for the plugin
if one does not exist yet, then add the plugin source file and the module declaration:

The example here is for a plugin that belongs to "the protocol" group.

```sh
src/protocols/<protocol>/
├── mod.rs          ← declares pub mod <plugin>;
└── <plugin>.rs     ← the plugin implementation
```

Expose the new protocol module from `src/protocols/mod.rs`:

```rust
pub mod <protocol>;
```

### 2. Define the plugin struct

The struct holds every parameter the plugin needs between `initialize` and
`execute`. Fields should mirror the CLI arguments declared in `meta()`.

```rust
pub struct ExamplePlugin {
    message: String,
    fail: bool,
}

impl ExamplePlugin {
    pub fn new() -> Self {
        Self { message: String::new(), fail: false }
    }
}

impl Default for ExamplePlugin {
    fn default() -> Self { Self::new() }
}
```

### 3. Implement `Plugin::meta`

`meta()` returns a `PluginMeta` built with the `plugin_meta!` macro. The macro
derives the plugin **name** and **category** from the Rust module path
automatically.

| Module path | Derived name |
|---|---|
| `iottack::protocols::http::banner` | `http/banner` |
| `iottack::protocols::network::tcp_banner` | `network/tcp-banner` |
| `iottack::protocols::example::example` | `example/example` |

The `args` slice describes every CLI flag. `main.rs` reads this slice to build
the clap subcommand dynamically.

```rust
fn meta(&self) -> PluginMeta {
    plugin_meta!(
        summary: "Example plugin, shows the full plugin authoring pattern",
        description: "A reference plugin that exercises every part of the Plugin \
                      API: initialize, execute, teardown, CLI arguments, findings \
                      at multiple severity levels, and the inventory registration \
                      macro.",
        needs_root: false,
        args: &[
            CliArg {
                name: "message",        // config key; becomes --message on the CLI
                short: Some('m'),
                help: "Text to include in the Info finding",
                value_name: "TEXT",
                default: Some("hello from example plugin"),
                is_flag: false,
            },
            CliArg {
                name: "fail",
                short: Some('x'),
                help: "Emit a High finding and exit with status Fail",
                value_name: "",
                default: None,
                is_flag: true,          // presence sets config key to "true"
            },
        ],
    )
}
```

### 4. Implement `Plugin::initialize`

`initialize` is called once before `execute`. Read every CLI argument from
`config` and store the values on `self`.

| Method | When to use |
|---|---|
| `config.get_or(key, default)` | String value with a fallback |
| `config.parse_or(key, default)` | Typed value (`u16`, `u64`, …) with a fallback |
| `config.require(key)` | Value that must be present — returns `Err` if missing |

```rust
fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
    self.message = config.get_or("message", "hello from example plugin");
    self.fail    = config.get("fail") == Some("true");
    Ok(())
}
```

### 5. Implement `Plugin::execute`

`execute` contains the core test logic. Create a `PluginResult`, add
`PluginFinding` values, and call `result.finish(status)` before returning.

**Severity levels** (lowest to highest): `Info` -> `Low` -> `Medium` -> `High` -> `Critical`

Use `PluginFinding::with_evidence` to attach the raw data that triggered a
finding: a banner, a header value, a captured packet and so on. Evidence is
shown in the text output and preserved in JSON results.

```rust
fn execute(&mut self) -> Result<PluginResult> {
    let mut result = PluginResult::new(self.meta().name);

    // Neutral observation — always emitted.
    result.add(PluginFinding::new(
        Severity::Info,
        format!("Example plugin executed: {}", self.message),
        "Informational finding describing an observed property of the target.",
    ));

    // Conditional finding with evidence.
    if self.fail {
        result.add(
            PluginFinding::new(
                Severity::High,
                "Simulated failure",
                "The --fail flag was set.",
            )
            .with_evidence("flag: --fail was present"),
        );
        result.finish(PluginStatus::Fail);
        return Ok(result);
    }

    result.finish(PluginStatus::Pass);
    Ok(result)
}
```

Early-return with `PluginStatus::Fail` for expected failure conditions such as
a refused connection or a missing required argument. Reserve `Err(...)` / `?`
for truly unexpected failures.

### 6. Implement `Plugin::teardown` (optional)

`teardown` is always called after `execute`, even when `execute` returned an
error. Use it to close sockets, file handles or serial ports. The default
implementation is a no-op. Please omit this method if there is nothing to release.

```rust
fn teardown(&mut self) -> Result<()> {
    Ok(())
}
```

### 7. Register the plugin

Add a single line at the bottom of the file. The framework collects all
registered factories at startup via the `inventory` crate. Thus, no changes to
`main.rs` or any registry file are needed.

```rust
inventory::submit! {
    crate::PluginFactory(|| Box::new(ExamplePlugin::new()) as Box<dyn crate::Plugin>)
}
```

### 8. Add documentation

Create a Markdown file at
`documentation/src/plugins/<protocol>/<plugin-name>.md` and add it to
`documentation/src/SUMMARY.md`. See
[http - banner](./plugins/http/http-banner.md) for an example of the expected
structure: one-liner, usage block, description, checks table with severities,
options table and example commands.

### Running the example plugin

```sh
# Pass status with default message
iottack example example

# Custom message
iottack example example --message "testing 1 2 3"

# Trigger the High finding and Fail status
iottack example example --fail

# Save JSON output
iottack example example --fail --output result.json --format json
```

## Running the tests

```sh
cargo test
```

The test suite covers the core types (`PluginConfig`, `PluginFinding`,
`PluginResult`, `Severity`, `Category`, `PluginRegistry`) and the
output-formatting helpers in `main.rs`. Doc-tests embedded in the public API
are run as part of the same `cargo test` invocation.
