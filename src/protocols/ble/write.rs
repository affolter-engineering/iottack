use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::fuzzing::{FuzzEngine, FuzzTransport};
use crate::plugin_meta;
use anyhow::Result;

/// BLE write transport structure containing the runtime handle, characteristic and response flag
struct BleWriteTransport {
    handle: tokio::runtime::Handle,
    characteristic: bluer::gatt::remote::Characteristic,
    no_response: bool,
}

/// Implementation of the FuzzTransport trait for BLE write operations
impl FuzzTransport for BleWriteTransport {
    fn send_recv(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let payload = payload.to_vec();
        let ch = &self.characteristic;
        let no_response = self.no_response;
        let hex: String = payload
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::debug!(
            bytes = payload.len(),
            method = if no_response {
                "write-no-rsp"
            } else {
                "write-with-response"
            },
            payload = hex,
            "fuzz write"
        );
        self.handle.block_on(async move {
            if no_response {
                ch.write_ext(
                    &payload,
                    &bluer::gatt::remote::CharacteristicWriteRequest {
                        op_type: bluer::gatt::WriteOp::Command,
                        ..Default::default()
                    },
                )
                .await?;
            } else {
                ch.write(&payload).await?;
            }
            let flags = ch.flags().await.unwrap_or_default();
            if flags.read {
                let response = ch.read().await.unwrap_or_default();
                tracing::debug!(bytes = response.len(), "read response");
                Ok(response)
            } else {
                Ok::<Vec<u8>, anyhow::Error>(Vec::new())
            }
        })
    }
}

/// Implementation of the Default trait for WritePlugin
pub struct WritePlugin {
    address: String,
    characteristic: String,
    value: String,
    hex: bool,
    no_response: bool,
    adapter_name: String,
    disconnect: bool,
    // fuzzing mode
    fuzz: bool,
    iterations: u32,
    charset: Option<String>,
    length: usize,
    wordlist: Option<String>,
    delay_ms: u64,
    suffix: String,
    patterns: Vec<String>,
    payload_sets: Option<String>,
}

/// Implementation of the constructor and default values for WritePlugin
impl WritePlugin {
    pub fn new() -> Self {
        Self {
            address: String::new(),
            characteristic: String::new(),
            value: String::new(),
            hex: false,
            no_response: false,
            adapter_name: String::new(),
            disconnect: true,
            fuzz: false,
            iterations: 1,
            charset: None,
            length: 16,
            wordlist: None,
            delay_ms: 0,
            suffix: String::new(),
            patterns: Vec::new(),
            payload_sets: None,
        }
    }
}

/// Implementation of the Default trait for WritePlugin
impl Default for WritePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the Plugin trait for WritePlugin
impl Plugin for WritePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Write a value to a BLE GATT characteristic, or fuzz it",
            description: "Connects to the specified Bluetooth Low Energy device, locates the \
                          given GATT characteristic UUID across all services, and either writes \
                          a single value or iterates the built-in fuzz payload set. \
                          In single-write mode the value is a UTF-8 string by default; pass \
                          --hex to supply raw bytes. In fuzz mode (--fuzz) the --value arg is \
                          ignored and the engine sends null bytes, long strings, format strings, \
                          boundary values and control characters, reading back any response and \
                          scanning it for error strings and crash indicators.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "address",
                    short: Some('d'),
                    help: "Bluetooth address of the target device (e.g., AA:BB:CC:DD:EE:FF)",
                    value_name: "ADDR",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "characteristic",
                    short: Some('c'),
                    help: "UUID of the GATT characteristic to write",
                    value_name: "UUID",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "value",
                    short: Some('V'),
                    help: "Value to write; UTF-8 string unless --hex is set (ignored with --fuzz)",
                    value_name: "DATA",
                    default: Some(""),
                    is_flag: false
                },
                CliArg {
                    name: "hex",
                    short: Some('x'),
                    help: "Treat VALUE as hex bytes (space-, colon-, or no-separator)",
                    value_name: "",
                    default: None,
                    is_flag: true
                },
                CliArg {
                    name: "no-response",
                    short: Some('n'),
                    help: "Use write-without-response for every write",
                    value_name: "",
                    default: None,
                    is_flag: true
                },
                CliArg {
                    name: "adapter",
                    short: Some('a'),
                    help: "Bluetooth adapter to use (e.g. hci0); defaults to first available",
                    value_name: "NAME",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "no-disconnect",
                    short: None,
                    help: "Leave the device connected after the operation",
                    value_name: "",
                    default: None,
                    is_flag: true
                },
                // fuzzing mode
                CliArg {
                    name: "fuzz",
                    short: Some('f'),
                    help: "Fuzz the characteristic instead of writing a single value",
                    value_name: "",
                    default: None,
                    is_flag: true
                },
                CliArg {
                    name: "iterations",
                    short: None,
                    help: "Times to repeat the full payload set (fuzz mode)",
                    value_name: "N",
                    default: Some("1"),
                    is_flag: false
                },
                CliArg {
                    name: "charset",
                    short: None,
                    help: "Characters to fuzz (one payload per char x length)",
                    value_name: "CHARS",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "length",
                    short: Some('l'),
                    help: "Max repeat length for charset payloads",
                    value_name: "N",
                    default: Some("16"),
                    is_flag: false
                },
                CliArg {
                    name: "wordlist",
                    short: Some('w'),
                    help: "Wordlist file (one entry per line); replaces built-in payloads",
                    value_name: "PATH",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "delay_ms",
                    short: None,
                    help: "Delay between payloads in milliseconds (fuzz mode)",
                    value_name: "MS",
                    default: Some("0"),
                    is_flag: false
                },
                CliArg {
                    name: "suffix",
                    short: Some('s'),
                    help: r"Bytes appended to every payload, e.g., '\r\n' (fuzz mode)",
                    value_name: "BYTES",
                    default: Some(""),
                    is_flag: false
                },
                CliArg {
                    name: "pattern",
                    short: None,
                    help: "Extra response pattern to flag (fuzz mode)",
                    value_name: "STRING",
                    default: None,
                    is_flag: false
                },
                CliArg {
                    name: "payload-set",
                    short: None,
                    help: "Named payload sets to add, comma-separated (digits,lowercase,uppercase,ascii)",
                    value_name: "SETS",
                    default: None,
                    is_flag: false
                },
            ],
        )
    }

    /// Initialize the plugin with the given configuration, parsing all relevant parameters
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.address = config.require("address")?.to_string();
        self.characteristic = config.require("characteristic")?.to_string();
        self.fuzz = config.get("fuzz") == Some("true");
        self.value = config.get_or("value", "");
        if !self.fuzz && self.value.is_empty() {
            anyhow::bail!("--value is required unless --fuzz is set");
        }
        self.hex = config.get("hex") == Some("true");
        self.no_response = config.get("no-response") == Some("true");
        self.adapter_name = config.get_or("adapter", "");
        self.disconnect = config.get("no-disconnect") != Some("true");
        self.iterations = config.parse_or("iterations", 1u32);
        self.charset = config.get("charset").map(|s| s.to_string());
        self.length = config.parse_or("length", 16usize);
        self.wordlist = config.get("wordlist").map(|s| s.to_string());
        self.delay_ms = config.parse_or("delay_ms", 0u64);
        self.suffix = config.get_or("suffix", "");
        if let Some(p) = config.get("pattern") {
            self.patterns.push(p.to_string());
        }
        self.payload_sets = config.get("payload-set").map(|s| s.to_string());
        Ok(())
    }

    /// Execute the plugin, setting up the Tokio runtime and calling the async write function
    fn execute(&mut self) -> Result<PluginResult> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
        rt.block_on(self.do_write())
    }
}

/// Perform the actual BLE write operation asynchronously, handling connection, payload and response
impl WritePlugin {
    async fn do_write(&self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        let addr: bluer::Address = match self.address.parse() {
            Ok(a) => a,
            Err(_) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Invalid Bluetooth address",
                    format!(
                        "'{}' is not a valid Bluetooth address. \
                         Expected format: AA:BB:CC:DD:EE:FF",
                        self.address
                    ),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        let target_uuid: bluer::Uuid = match self.characteristic.parse() {
            Ok(u) => u,
            Err(_) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Invalid characteristic UUID",
                    format!(
                        "'{}' is not a valid UUID. \
                         Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                        self.characteristic
                    ),
                ));
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
        };

        // Validate the single-write payload early so we fail fast before connecting.
        let payload = if !self.fuzz {
            match self.parse_payload() {
                Ok(b) => b,
                Err(e) => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        "Invalid value",
                        format!("{e}"),
                    ));
                    result.finish(PluginStatus::Fail);
                    return Ok(result);
                }
            }
        } else {
            Vec::new()
        };

        let session = match bluer::Session::new().await {
            Ok(s) => s,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Bluetooth not available",
                    format!(
                        "{e}\n\nEnsure the BlueZ daemon (bluetoothd) is running and the \
                         D-Bus system bus is accessible."
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let adapter_name = if self.adapter_name.is_empty() {
            let names = session.adapter_names().await.unwrap_or_default();
            tracing::debug!(adapters = ?names, "discovered adapters");
            match names.into_iter().next() {
                Some(n) => n,
                None => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        "No Bluetooth adapters found",
                        "No Bluetooth adapters were detected. Connect a Bluetooth adapter and \
                         ensure bluetoothd is running.",
                    ));
                    result.finish(PluginStatus::Pass);
                    return Ok(result);
                }
            }
        } else {
            self.adapter_name.clone()
        };

        tracing::debug!(adapter = adapter_name, "using adapter");
        let adapter = match session.adapter(&adapter_name) {
            Ok(a) => a,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot access adapter {adapter_name}"),
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let device = match adapter.device(addr) {
            Ok(d) => d,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot access device {addr}"),
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let was_connected = device.is_connected().await.unwrap_or(false);
        tracing::debug!(address = %addr, already_connected = was_connected, "device state");

        if !was_connected {
            tracing::debug!(address = %addr, "connecting");
            if let Err(e) = device.connect().await {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot connect to {addr}"),
                    format!(
                        "{e}\n\nThe device may be out of range, powered off or require pairing. \
                         Run 'iottack ble scan' first to confirm it is advertising."
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        }

        tracing::debug!(address = %addr, "connected");
        tracing::debug!(address = %addr, uuid = %target_uuid, "searching for characteristic");
        let ch = match self.find_characteristic(&device, target_uuid).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Characteristic {target_uuid} not found"),
                    format!(
                        "No characteristic with UUID {target_uuid} was found on device {addr}. \
                         Run 'iottack ble device --address {addr}' to list available characteristics."
                    ),
                ));
                self.maybe_disconnect(&device, was_connected).await;
                result.finish(PluginStatus::Fail);
                return Ok(result);
            }
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "Cannot enumerate GATT services",
                    format!("{e}"),
                ));
                self.maybe_disconnect(&device, was_connected).await;
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let flags = ch.flags().await.unwrap_or_default();
        tracing::debug!(uuid = %target_uuid, flags = self.format_flags(&flags), "characteristic found");
        if !flags.write && !flags.write_without_response {
            result.add(PluginFinding::new(
                Severity::Low,
                format!("Characteristic {target_uuid} is not writable"),
                format!(
                    "The characteristic does not expose the write or \
                     write-without-response property.\nFlags: {}",
                    self.format_flags(&flags)
                ),
            ));
            self.maybe_disconnect(&device, was_connected).await;
            result.finish(PluginStatus::Fail);
            return Ok(result);
        }

        if self.fuzz {
            tracing::info!(address = %addr, uuid = %target_uuid, iterations = self.iterations, "starting fuzz mode");
            self.run_fuzz(&mut result, ch, addr, target_uuid).await?;
        } else {
            let hex: String = payload
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            tracing::info!(address = %addr, uuid = %target_uuid, bytes = payload.len(), payload = hex, "single write");
            self.run_single_write(&mut result, ch, addr, &payload).await;
        }

        self.maybe_disconnect(&device, was_connected).await;
        Ok(result)
    }

    async fn run_single_write(
        &self,
        result: &mut PluginResult,
        ch: bluer::gatt::remote::Characteristic,
        addr: bluer::Address,
        payload: &[u8],
    ) {
        let ch_uuid = ch.uuid().await.unwrap_or(bluer::Uuid::default());
        let hex_repr = payload
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");

        let write_result = if self.no_response {
            ch.write_ext(
                payload,
                &bluer::gatt::remote::CharacteristicWriteRequest {
                    op_type: bluer::gatt::WriteOp::Command,
                    ..Default::default()
                },
            )
            .await
        } else {
            ch.write(payload).await
        };

        match write_result {
            Ok(()) => {
                result.add(
                    PluginFinding::new(
                        Severity::Info,
                        format!("Write successful to {ch_uuid}"),
                        format!(
                            "Device:         {addr}\n  \
                             Characteristic: {ch_uuid}\n  \
                             Method:         {}\n  \
                             Bytes written:  {}\n  \
                             Payload (hex):  {hex_repr}",
                            if self.no_response {
                                "write-without-response"
                            } else {
                                "write-with-response"
                            },
                            payload.len(),
                        ),
                    )
                    .with_evidence(format!(
                        "address={addr}, characteristic={ch_uuid}, bytes={}, payload={hex_repr}",
                        payload.len()
                    )),
                );
                result.finish(PluginStatus::Pass);
            }
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Low,
                    format!("Write failed to {ch_uuid}"),
                    format!("{e}"),
                ));
                result.finish(PluginStatus::Fail);
            }
        }
    }

    async fn run_fuzz(
        &self,
        result: &mut PluginResult,
        ch: bluer::gatt::remote::Characteristic,
        addr: bluer::Address,
        uuid: bluer::Uuid,
    ) -> Result<()> {
        let handle = tokio::runtime::Handle::current();
        let no_response = self.no_response;
        let iterations = self.iterations;
        let delay_ms = self.delay_ms;
        let suffix = self.suffix.clone();
        let wordlist = self.wordlist.clone();
        let charset = self.charset.clone();
        let length = self.length;
        let extra_patterns: Vec<String> = self.patterns.clone();
        let payload_sets = self.payload_sets.clone();
        let context = format!("{addr}/{uuid}");

        let matches = tokio::task::block_in_place(move || {
            let extra: Vec<&str> = extra_patterns.iter().map(String::as_str).collect();
            let mut engine = FuzzEngine::new(iterations)
                .with_delay_ms(delay_ms)
                .with_suffix(&suffix)
                .with_extra_patterns(&extra);

            if wordlist.is_some() || charset.is_some() || payload_sets.is_some() {
                engine = engine.with_payloads(&[]);
            }
            if let Some(ref path) = wordlist {
                engine = engine.with_wordlist(path)?;
            }
            if let Some(ref chars) = charset {
                engine = engine.with_charset(chars, length);
            }
            if let Some(ref sets) = payload_sets {
                engine = engine.with_payload_sets(sets)?;
            }

            let mut transport = BleWriteTransport {
                handle,
                characteristic: ch,
                no_response,
            };
            engine.run(&mut transport)
        })?;

        if matches.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No interesting responses",
                format!(
                    "All payloads x {iterations} iteration(s) produced no interesting \
                     response from {context}.",
                ),
            ));
            result.finish(PluginStatus::Pass);
        } else {
            for finding in FuzzEngine::to_findings(&matches, &context) {
                result.add(finding);
            }
            let has_critical = matches
                .iter()
                .any(|m| matches!(m.severity, Severity::Critical | Severity::High));
            result.finish(if has_critical {
                PluginStatus::Fail
            } else {
                PluginStatus::Pass
            });
        }

        Ok(())
    }

    async fn find_characteristic(
        &self,
        device: &bluer::Device,
        uuid: bluer::Uuid,
    ) -> Result<Option<bluer::gatt::remote::Characteristic>> {
        let services = device.services().await?;
        tracing::debug!(services = services.len(), "enumerating services");
        for service in &services {
            let svc_uuid = service.uuid().await.unwrap_or_default();
            for ch in service.characteristics().await.unwrap_or_default() {
                let ch_uuid = ch.uuid().await.unwrap_or_default();
                tracing::trace!(service = %svc_uuid, characteristic = %ch_uuid, "checking");
                if ch_uuid == uuid {
                    tracing::debug!(service = %svc_uuid, characteristic = %ch_uuid, "matched");
                    return Ok(Some(ch));
                }
            }
        }
        Ok(None)
    }

    fn parse_payload(&self) -> anyhow::Result<Vec<u8>> {
        if self.hex {
            let stripped = self.value.replace([' ', ':', '-'], "");
            tracing::debug!(raw = self.value, stripped = stripped, "parsing hex payload");
            if stripped.len() % 2 != 0 {
                anyhow::bail!("HEX string has an odd number of nibbles: '{}'", self.value);
            }
            let bytes: anyhow::Result<Vec<u8>> = (0..stripped.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&stripped[i..i + 2], 16).map_err(|_| {
                        anyhow::anyhow!(
                            "invalid hex byte '{}' in '{}'",
                            &stripped[i..i + 2],
                            self.value
                        )
                    })
                })
                .collect();
            let bytes = bytes?;
            let hex_repr: String = bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            tracing::info!(bytes = bytes.len(), payload = hex_repr, "payload (hex)");
            Ok(bytes)
        } else {
            let bytes = self.value.as_bytes().to_vec();
            let hex_repr: String = bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            tracing::info!(
                raw = self.value,
                bytes = bytes.len(),
                payload = hex_repr,
                "payload"
            );
            Ok(bytes)
        }
    }

    fn format_flags(&self, flags: &bluer::gatt::CharacteristicFlags) -> String {
        let mut props: Vec<&str> = Vec::new();
        if flags.read {
            props.push("read")
        }
        if flags.write {
            props.push("write")
        }
        if flags.write_without_response {
            props.push("write-no-rsp")
        }
        if flags.notify {
            props.push("notify")
        }
        if flags.indicate {
            props.push("indicate")
        }
        if props.is_empty() {
            "none".to_string()
        } else {
            props.join(", ")
        }
    }

    async fn maybe_disconnect(&self, device: &bluer::Device, was_connected: bool) {
        if self.disconnect && !was_connected {
            let _ = device.disconnect().await;
        }
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(WritePlugin::new()) as Box<dyn crate::Plugin>)
}
