//! Logic analyzer capture plugin using libsigrok-sys raw FFI bindings.
//!
//! GPL-3.0-or-later governs the libsigrok-sys crate and the linked libsigrok C
//! library. The Rust source in this file is MIT-licensed as part of iottack.

use crate::core::{
    CliArg, Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use libsigrok_sys::sigrok as sr;
use libsigrok_sys::sigrok::{
    GSList, GVariant, gboolean, sr_channel, sr_configkey_SR_CONF_LIMIT_SAMPLES,
    sr_configkey_SR_CONF_SAMPLERATE, sr_context, sr_datafeed_logic, sr_datafeed_packet,
    sr_dev_driver, sr_dev_inst, sr_error_code_SR_OK, sr_packettype_SR_DF_LOGIC, sr_session,
};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

// Bindgen emits _GSList and sr_channel as opaque types when the GLib headers are
// not fully visible to clang (common in CI). These repr(C) mirrors match the
// stable C struct layouts and let us read fields without relying on bindgen.

/// Mirror of GLib `struct _GSList { gpointer data; GSList *next; }`.
#[repr(C)]
struct GSListRaw {
    data: *mut c_void,
    next: *mut GSListRaw,
}

/// Mirror of libsigrok `struct sr_channel { int index; int type; gboolean enabled; char *name; … }`.
#[repr(C)]
struct SrChannelRaw {
    index:   c_int,
    type_:   c_int,
    enabled: c_int, // gboolean = gint = c_int
    name:    *const c_char,
}

// GLib functions not in libsigrok-sys but present in the linked libglib2.0.
unsafe extern "C" {
    fn g_variant_new_uint64(value: u64) -> *mut GVariant;
    fn g_variant_get_uint64(value: *const GVariant) -> u64;
    fn g_variant_unref(value: *mut GVariant);
    fn g_slist_free(list: *mut GSList);
}

/// Wrapper around a libsigrok context pointer. Ensures proper initialization and cleanup.
struct SrCtx(*mut sr_context);

/// Initializes a new libsigrok context.
impl SrCtx {
    fn init() -> Result<Self> {
        let mut ctx: *mut sr_context = ptr::null_mut();
        let rc = unsafe { sr::sr_init(&mut ctx) };
        if rc != sr_error_code_SR_OK || ctx.is_null() {
            anyhow::bail!("sr_init failed ({})", rc);
        }
        unsafe { sr::sr_log_loglevel_set(0) };
        Ok(SrCtx(ctx))
    }
}

/// Ensures proper cleanup of a libsigrok context when it goes out of scope.
impl Drop for SrCtx {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sr::sr_exit(self.0) };
        }
    }
}

/// Wrapper around a libsigrok context pointer. Ensures proper initialization and cleanup.
unsafe fn iter_drivers(head: *mut *mut sr_dev_driver) -> Vec<*mut sr_dev_driver> {
    let mut out = Vec::new();
    if head.is_null() {
        return out;
    }
    let mut p = head;
    unsafe {
        while !(*p).is_null() {
            out.push(*p);
            p = p.add(1);
        }
    }
    out
}

/// Iterates over a GSList and collects the data pointers into a vector.
unsafe fn iter_gslist<T>(list: *mut GSList) -> Vec<*mut T> {
    let mut out = Vec::new();
    let mut node = list as *mut GSListRaw;
    while !node.is_null() {
        let data = unsafe { (*node).data as *mut T };
        if !data.is_null() {
            out.push(data);
        }
        node = unsafe { (*node).next };
    }
    out
}

/// Converts a C string pointer to a Rust String, returning an empty string if the pointer is null.
unsafe fn cstr_or_empty(p: *const std::os::raw::c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

/// Capture plugin for acquiring digital samples from a sigrok-compatible logic analyzer.
pub struct CapturePlugin {
    driver: String,
    samples: u64,
    samplerate: u64,
    output: String,
    channels: Vec<String>,
}

/// Provides a default implementation for the CapturePlugin, allowing easy instantiation with default values.
impl CapturePlugin {
    pub fn new() -> Self {
        Self {
            driver: String::new(),
            samples: 1_000,
            samplerate: 1_000_000,
            output: String::new(),
            channels: Vec::new(),
        }
    }
}

/// Constructor for the CapturePlugin, initializing default values for driver, samples, sample rate, output and channels.
impl Default for CapturePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements the core logic for the CapturePlugin, including device scanning and sample capturing.
impl Plugin for CapturePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "Capture digital samples from a sigrok-compatible logic analyzer",
            description: "Connects to a sigrok-supported logic analyzer and captures raw digital \
                          samples. Without --driver the plugin scans for connected devices and \
                          lists them. With --driver it opens a session (e.g., 'demo', 'fx2lafw', \
                          'saleae-logic16'), sets the sample rate, runs a capture, and reports \
                          which channels are active. Active bus traffic on JTAG, SWD, SPI or \
                          I2C lines is flagged as a security finding because it may indicate a \
                          live debug interface.",
            needs_root: false,
            args: &[
                CliArg {
                    name: "driver",
                    short: Some('d'),
                    help: "sigrok driver name to use (e.g., 'demo', 'fx2lafw'). \
                           Omit to scan and list connected devices.",
                    value_name: "DRIVER",
                    default: Some(""),
                    is_flag: false,
                },
                CliArg {
                    name: "samples",
                    short: Some('n'),
                    help: "Number of samples to capture (default 1000).",
                    value_name: "COUNT",
                    default: Some("1000"),
                    is_flag: false,
                },
                CliArg {
                    name: "samplerate",
                    short: Some('r'),
                    help: "Sample rate in Hz (default 1000000 = 1 MHz).",
                    value_name: "HZ",
                    default: Some("1000000"),
                    is_flag: false,
                },
                CliArg {
                    name: "channels",
                    short: Some('c'),
                    help: "Channels to monitor: a single name (D0), a comma-separated list \
                           (D0,D2,D4) or a range (D0-D3). Ranges and lists may be mixed \
                           (D0-D2,D7). Omit to capture all channels.",
                    value_name: "CHANNELS",
                    default: Some(""),
                    is_flag: false,
                },
                CliArg {
                    name: "dump_file",
                    short: Some('w'),
                    help: "File path for a raw binary capture dump. \
                           Leave empty to skip file output.",
                    value_name: "FILE",
                    default: Some(""),
                    is_flag: false,
                },
            ],
        )
    }

    /// Initializes the plugin with the provided configuration, parsing driver, sample count, sample rate, channels, and output file.
    fn initialize(&mut self, config: &PluginConfig) -> Result<()> {
        self.driver = config.get_or("driver", "");
        self.samples = config.parse_or("samples", 1_000u64);
        self.samplerate = config.parse_or("samplerate", 1_000_000u64);
        self.channels = parse_channels(&config.get_or("channels", ""));
        self.output = config.get_or("dump_file", "");
        Ok(())
    }

    /// Executes the plugin, either scanning for devices or capturing samples based on the configuration.
    fn execute(&mut self) -> Result<PluginResult> {
        let result = PluginResult::new(self.meta().name);

        if self.driver.is_empty() {
            return self.scan_devices(result);
        }

        self.capture_samples(result)
    }
}

/// Implements the core logic for the CapturePlugin, including device scanning and sample capturing.
impl CapturePlugin {
    fn scan_devices(&self, mut result: PluginResult) -> Result<PluginResult> {
        let ctx = match SrCtx::init() {
            Ok(c) => c,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    "sigrok initialization failed",
                    format!(
                        "{e}\n\nEnsure libsigrok is installed and your user has permission \
                         to access USB/serial devices (e.g., membership in the 'plugdev' group)."
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        struct DevInfo {
            vendor: String,
            model: String,
            version: String,
            serial: String,
            connid: String,
            driver_name: String,
        }

        let mut all_devices: Vec<DevInfo> = Vec::new();

        unsafe {
            let drivers = iter_drivers(sr::sr_driver_list(ctx.0));
            for &driver in &drivers {
                if sr::sr_driver_init(ctx.0, driver) != sr_error_code_SR_OK {
                    continue;
                }
                let list = sr::sr_driver_scan(driver, ptr::null_mut());
                let devices = iter_gslist::<sr_dev_inst>(list);
                for &sdi in &devices {
                    all_devices.push(DevInfo {
                        vendor: cstr_or_empty(sr::sr_dev_inst_vendor_get(sdi)),
                        model: cstr_or_empty(sr::sr_dev_inst_model_get(sdi)),
                        version: cstr_or_empty(sr::sr_dev_inst_version_get(sdi)),
                        serial: cstr_or_empty(sr::sr_dev_inst_sernum_get(sdi)),
                        connid: cstr_or_empty(sr::sr_dev_inst_connid_get(sdi)),
                        driver_name: cstr_or_empty((*driver).name),
                    });
                }
                if !list.is_null() {
                    g_slist_free(list);
                }
            }
        }

        if all_devices.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No sigrok-supported logic analyzers found",
                "No devices were detected. Connect a supported logic analyzer and retry, \
                 or use the 'demo' driver (--driver demo) for a simulated device.",
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!("{} logic analyzer(s) detected", all_devices.len()),
            "Pass --driver <DRIVER> with one of the driver names below to start a capture.",
        ));

        for dev in &all_devices {
            let evidence = format!(
                "vendor={}, model={}, version={}, serial={}, connection={}, driver={}",
                dev.vendor, dev.model, dev.version, dev.serial, dev.connid, dev.driver_name,
            );
            result.add(
                PluginFinding::new(
                    Severity::Info,
                    format!("{} {} (driver: {})", dev.vendor, dev.model, dev.driver_name,),
                    format!(
                        "Version: {}  Serial: {}  Connection: {}",
                        dev.version, dev.serial, dev.connid,
                    ),
                )
                .with_evidence(evidence),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }

    /// Captures samples from the specified logic analyzer device using the configured driver.
    fn capture_samples(&mut self, mut result: PluginResult) -> Result<PluginResult> {
        let ctx = match SrCtx::init() {
            Ok(c) => c,
            Err(e) => {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot connect to device via driver '{}'", self.driver),
                    format!(
                        "{e}\n\nRun without --driver to list available drivers or try \
                         '--driver demo' for a simulated capture."
                    ),
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }
        };

        let driver_cname = CString::new(self.driver.as_str()).unwrap();

        let (driver, sdi, scan_list) = unsafe {
            let drivers = iter_drivers(sr::sr_driver_list(ctx.0));

            let found = drivers.into_iter().find(|&d| {
                !(*d).name.is_null() && CStr::from_ptr((*d).name) == driver_cname.as_c_str()
            });

            let driver = match found {
                Some(d) => d,
                None => {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        format!("Driver '{}' not found", self.driver),
                        "Run without --driver to list available drivers or try \
                         '--driver demo' for a simulated capture.",
                    ));
                    result.finish(PluginStatus::Pass);
                    return Ok(result);
                }
            };

            if sr::sr_driver_init(ctx.0, driver) != sr_error_code_SR_OK {
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot connect to device via driver '{}'", self.driver),
                    "The driver name is recognized but no accessible device was found. \
                     On Linux this usually means a USB permission problem:\n\
                     \n\
                     1. Add your user to the 'plugdev' group:\n\
                     \x20   sudo usermod -aG plugdev $USER\n\
                     2. Install udev rules (if not already present):\n\
                     \x20   sudo apt install sigrok  # Debian/Ubuntu\n\
                     \x20   or copy rules from /usr/lib/udev/rules.d/\n\
                     3. Reconnect the device and log out/in.\n\
                     \n\
                     Alternatively try '--driver demo' for a simulated capture.",
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }

            let list = sr::sr_driver_scan(driver, ptr::null_mut());
            let devices = iter_gslist::<sr_dev_inst>(list);

            let sdi = match devices.into_iter().next() {
                Some(s) => s,
                None => {
                    if !list.is_null() {
                        g_slist_free(list);
                    }
                    result.add(PluginFinding::new(
                        Severity::Info,
                        format!("No device found via driver '{}'", self.driver),
                        "Alternatively try '--driver demo' for a simulated capture.",
                    ));
                    result.finish(PluginStatus::Pass);
                    return Ok(result);
                }
            };

            (driver, sdi, list)
        };

        let mut capture_buf: Vec<u8> = Vec::new();
        let actual_rate;

        unsafe {
            if sr::sr_dev_open(sdi) != sr_error_code_SR_OK {
                if !scan_list.is_null() {
                    g_slist_free(scan_list);
                }
                result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Cannot open device via driver '{}'", self.driver),
                    "Check device connectivity and USB permissions.",
                ));
                result.finish(PluginStatus::Pass);
                return Ok(result);
            }

            if !self.channels.is_empty() {
                configure_channels(sdi, &self.channels, &mut result);
            }

            let mut session: *mut sr_session = ptr::null_mut();
            sr::sr_session_new(ctx.0, &mut session);
            sr::sr_session_dev_add(session, sdi);

            let sr_gv = g_variant_new_uint64(self.samplerate);
            sr::sr_config_set(sdi, ptr::null(), sr_configkey_SR_CONF_SAMPLERATE, sr_gv);

            let limit_gv = g_variant_new_uint64(self.samples);
            sr::sr_config_set(
                sdi,
                ptr::null(),
                sr_configkey_SR_CONF_LIMIT_SAMPLES,
                limit_gv,
            );

            sr::sr_session_datafeed_callback_add(
                session,
                Some(datafeed_cb),
                &mut capture_buf as *mut Vec<u8> as *mut c_void,
            );

            sr::sr_session_start(session);
            sr::sr_session_run(session);

            let mut rate_gv: *mut GVariant = ptr::null_mut();
            actual_rate = if sr::sr_config_get(
                driver,
                sdi,
                ptr::null(),
                sr_configkey_SR_CONF_SAMPLERATE,
                &mut rate_gv,
            ) == sr_error_code_SR_OK
                && !rate_gv.is_null()
            {
                let r = g_variant_get_uint64(rate_gv);
                g_variant_unref(rate_gv);
                r
            } else {
                self.samplerate
            };

            sr::sr_session_stop(session);
            sr::sr_dev_close(sdi);
            sr::sr_session_dev_remove_all(session);
            sr::sr_session_destroy(session);

            if !scan_list.is_null() {
                g_slist_free(scan_list);
            }
        }

        if !self.output.is_empty() && !capture_buf.is_empty() {
            match std::fs::write(&self.output, &capture_buf) {
                Ok(()) => result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Capture written to '{}'", self.output),
                    format!("{} bytes saved (raw binary).", capture_buf.len()),
                )),
                Err(e) => result.add(PluginFinding::new(
                    Severity::Info,
                    format!("Failed to write output file '{}'", self.output),
                    format!("{e}"),
                )),
            }
        }

        let monitored_label = if self.channels.is_empty() {
            "all channels".to_string()
        } else {
            self.channels.join(", ")
        };
        analyze_capture(
            &mut result,
            &capture_buf,
            actual_rate,
            &monitored_label,
            &self.channels,
        );
        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

/// Callback function for handling incoming data feed packets from the logic analyzer.
unsafe extern "C" fn datafeed_cb(
    _sdi: *const sr_dev_inst,
    packet: *const sr_datafeed_packet,
    cb_data: *mut c_void,
) {
    if packet.is_null() || cb_data.is_null() {
        return;
    }
    unsafe {
        if (*packet).type_ != sr_packettype_SR_DF_LOGIC as u16 {
            return;
        }
        let logic = &*((*packet).payload as *const sr_datafeed_logic);
        if logic.data.is_null() || logic.length == 0 {
            return;
        }
        let bytes = std::slice::from_raw_parts(logic.data as *const u8, logic.length as usize);
        let buf = &mut *(cb_data as *mut Vec<u8>);
        buf.extend_from_slice(bytes);
    }
}

/// Configures the specified channels on a given device instance, enabling only the requested channels and disabling all others.
unsafe fn configure_channels(
    sdi: *mut sr_dev_inst,
    channels: &[String],
    result: &mut PluginResult,
) {
    let ch_list = unsafe { sr::sr_dev_inst_channels_get(sdi) };
    let all_ch = unsafe { iter_gslist::<sr_channel>(ch_list) };

    for &ch in &all_ch {
        let _ = unsafe { sr::sr_dev_channel_enable(ch, 0 as gboolean) };
    }

    for name in channels {
        let cname = match CString::new(name.as_str()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let found = all_ch.iter().find(|&&ch| unsafe {
            let raw = ch as *const SrChannelRaw;
            !(*raw).name.is_null() && CStr::from_ptr((*raw).name) == cname.as_c_str()
        });
        match found {
            Some(&ch) => {
                if unsafe { sr::sr_dev_channel_enable(ch, 1 as gboolean) } != sr_error_code_SR_OK {
                    result.add(PluginFinding::new(
                        Severity::Info,
                        format!("Could not enable channel {name}"),
                        "Verify the channel name matches the device's naming scheme \
                         (e.g. D0-D7 for most 8-channel analyzers).",
                    ));
                }
            }
            None => result.add(PluginFinding::new(
                Severity::Info,
                format!("Channel {name} not found on device"),
                "Verify the channel name matches the device's naming scheme.",
            )),
        }
    }
}

/// Parses a comma-separated list of channel specifications into a vector of individual channel names.
fn parse_channels(spec: &str) -> Vec<String> {
    if spec.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if let Some((start, end)) = parse_channel_range(token) {
            for i in start..=end {
                out.push(format!("D{i}"));
            }
        } else if !token.is_empty() {
            out.push(token.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Parses a channel range specification string into a vector of individual channel names.
fn parse_channel_range(s: &str) -> Option<(u8, u8)> {
    let inner = s.strip_prefix('D').unwrap_or(s);
    let (lhs, rhs) = inner.split_once('-')?;
    let start: u8 = lhs.parse().ok()?;
    let end_str = rhs.strip_prefix('D').unwrap_or(rhs);
    let end: u8 = end_str.parse().ok()?;
    if start <= end {
        Some((start, end))
    } else {
        None
    }
}

/// Determines the severity level based on the percentage of active samples.
fn severity_for_pct(pct: usize) -> Severity {
    if pct >= 50 {
        Severity::High
    } else if pct >= 10 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Analyzes a logic analyzer capture buffer, reporting per-channel activity and overall statistics.
fn analyze_capture(
    result: &mut PluginResult,
    data: &[u8],
    samplerate: u64,
    monitored: &str,
    channel_filter: &[String],
) {
    let total = data.len();
    if total == 0 {
        result.add(PluginFinding::new(
            Severity::Info,
            "Empty capture buffer",
            "The device returned zero bytes. Verify sample count and device connectivity.",
        ));
        return;
    }

    let duration_us = if samplerate > 0 {
        (total as u64 * 1_000_000) / samplerate
    } else {
        0
    };

    // When the user requested specific channels, restrict per-channel reporting
    // to those bits. Otherwise scan all 8.
    let requested_bits: Vec<u8> = if channel_filter.is_empty() {
        (0u8..8).collect()
    } else {
        channel_filter
            .iter()
            .filter_map(|name| name.strip_prefix('D')?.parse().ok())
            .collect()
    };

    // Per-channel counts: how many samples had each bit set.
    let ch_counts: Vec<(u8, usize)> = requested_bits
        .iter()
        .map(|&bit| (bit, data.iter().filter(|&&b| b & (1 << bit) != 0).count()))
        .filter(|&(_, count)| count > 0)
        .collect();

    if ch_counts.is_empty() {
        result.add(PluginFinding::new(
            Severity::Info,
            "All channels idle during capture",
            format!(
                "Captured {total} samples ({duration_us} µs at {samplerate} Hz) - \
                 all monitored channel bits were low for the entire window. \
                 Monitored: {monitored}."
            ),
        ));
        return;
    }

    // Aggregate active count across the monitored channels only.
    let active = data
        .iter()
        .filter(|&&b| ch_counts.iter().any(|&(bit, _)| b & (1 << bit) != 0))
        .count();
    let idle = total - active;
    let active_pct = (active * 100) / total;
    let channel_list: String = ch_counts
        .iter()
        .map(|&(bit, _)| format!("D{bit}"))
        .collect::<Vec<_>>()
        .join(", ");

    result.add(
        PluginFinding::new(
            severity_for_pct(active_pct),
            format!(
                "Signal activity on {} channel(s): {}",
                ch_counts.len(),
                channel_list
            ),
            format!(
                "Monitored: {monitored}. {active} of {total} samples ({active_pct}%) showed \
                 at least one high channel over a {duration_us} µs window at {samplerate} Hz. \
                 Idle samples: {idle}. Active channels: {channel_list}."
            ),
        )
        .with_evidence(format!(
            "monitored={monitored}, total_samples={total}, active={active}, idle={idle}, \
             active_pct={active_pct}, active_channels=[{channel_list}], \
             samplerate_hz={samplerate}, duration_us={duration_us}"
        )),
    );

    // Per-channel findings.
    for &(bit, count) in &ch_counts {
        let pct = (count * 100) / total;
        let idle_ch = total - count;
        result.add(
            PluginFinding::new(
                severity_for_pct(pct),
                format!("D{bit}: {pct}% active ({count}/{total} samples)"),
                format!(
                    "Channel D{bit} was high in {count} of {total} samples ({pct}%) over \
                     {duration_us} µs at {samplerate} Hz. Idle samples: {idle_ch}."
                ),
            )
            .with_evidence(format!(
                "channel=D{bit}, active={count}, idle={idle_ch}, total={total}, \
                 active_pct={pct}, samplerate_hz={samplerate}, duration_us={duration_us}"
            )),
        );
    }

    if active_pct >= 5 {
        result.add(PluginFinding::new(
            Severity::Medium,
            "Sustained bus activity — possible debug interface",
            format!(
                "{active_pct}% of samples were active. Sustained traffic on {channel_list} \
                 may indicate a live JTAG, SWD, SPI or I2C interface. Confirm that debug \
                 ports are intentionally exposed and access is properly controlled."
            ),
        ));
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(CapturePlugin::new()) as Box<dyn crate::Plugin>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_channels_empty_returns_empty() {
        assert!(parse_channels("").is_empty());
    }

    #[test]
    fn parse_channels_single() {
        assert_eq!(parse_channels("D0"), vec!["D0"]);
    }

    #[test]
    fn parse_channels_list() {
        assert_eq!(parse_channels("D0,D2,D4"), vec!["D0", "D2", "D4"]);
    }

    #[test]
    fn parse_channels_range_d_prefix() {
        assert_eq!(parse_channels("D0-D3"), vec!["D0", "D1", "D2", "D3"]);
    }

    #[test]
    fn parse_channels_range_numeric() {
        assert_eq!(parse_channels("0-2"), vec!["D0", "D1", "D2"]);
    }

    #[test]
    fn parse_channels_mixed() {
        let mut got = parse_channels("D0-D2,D7");
        got.sort();
        assert_eq!(got, vec!["D0", "D1", "D2", "D7"]);
    }

    #[test]
    fn parse_channels_deduplicates() {
        assert_eq!(parse_channels("D0,D0,D1"), vec!["D0", "D1"]);
    }

    #[test]
    fn parse_channels_trims_whitespace() {
        assert_eq!(parse_channels("D0, D2 , D4"), vec!["D0", "D2", "D4"]);
    }

    #[test]
    fn parse_channel_range_returns_none_for_plain_name() {
        assert!(parse_channel_range("D0").is_none());
    }

    #[test]
    fn parse_channel_range_rejects_inverted_range() {
        assert!(parse_channel_range("D3-D0").is_none());
    }
}
