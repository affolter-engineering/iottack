use crate::core::{
    Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use libsigrok_sys::sigrok as sr;
use libsigrok_sys::sigrok::{
    GSList, sr_channel, sr_context, sr_dev_driver, sr_dev_inst, sr_error_code_SR_OK,
};
use std::ffi::CStr;
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

/// Device plugin for listing all sigrok-supported logic analyzers connected to the host.
unsafe extern "C" {
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

/// Iterates over a null-terminated array of device drivers and collects them into a vector.
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

/// Device plugin for listing all sigrok-supported logic analyzers connected to the host.
pub struct DevicePlugin;

/// Constructor for the DevicePlugin.
impl DevicePlugin {
    pub fn new() -> Self {
        Self
    }
}

/// Provides a default implementation for the DevicePlugin.
impl Default for DevicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements the Plugin trait for the DevicePlugin, providing metadata, initialization, and execution logic.
impl Plugin for DevicePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "List all sigrok-supported logic analyzers connected to this host",
            description: "Initializes a libsigrok context, probes every registered driver, and \
                          returns a finding for each discovered device. Each finding includes the \
                          vendor, model, firmware version, serial number, connection ID, driver \
                          name and the full list of channels exposed by the device.",
            needs_root: false,
            args: &[],
        )
    }

    /// Initializes the plugin. Currently, this is a no-op and always succeeds.
    fn initialize(&mut self, _config: &PluginConfig) -> Result<()> {
        Ok(())
    }

    /// Executes the plugin, probing for connected devices and collecting their information.
    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

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
            driver_longname: String,
            channels: Vec<(String, bool)>,
        }

        let mut devices: Vec<DevInfo> = Vec::new();

        unsafe {
            let drivers = iter_drivers(sr::sr_driver_list(ctx.0));
            for &driver in &drivers {
                if sr::sr_driver_init(ctx.0, driver) != sr_error_code_SR_OK {
                    continue;
                }
                let list = sr::sr_driver_scan(driver, ptr::null_mut());
                for &sdi in &iter_gslist::<sr_dev_inst>(list) {
                    let ch_list = sr::sr_dev_inst_channels_get(sdi);
                    let channels = iter_gslist::<sr_channel>(ch_list)
                        .into_iter()
                        .map(|ch| {
                            let raw = ch as *const SrChannelRaw;
                            let name = cstr_or_empty((*raw).name);
                            let enabled = (*raw).enabled != 0;
                            (name, enabled)
                        })
                        .collect();

                    let drv = sr::sr_dev_inst_driver_get(sdi);
                    devices.push(DevInfo {
                        vendor: cstr_or_empty(sr::sr_dev_inst_vendor_get(sdi)),
                        model: cstr_or_empty(sr::sr_dev_inst_model_get(sdi)),
                        version: cstr_or_empty(sr::sr_dev_inst_version_get(sdi)),
                        serial: cstr_or_empty(sr::sr_dev_inst_sernum_get(sdi)),
                        connid: cstr_or_empty(sr::sr_dev_inst_connid_get(sdi)),
                        driver_name: if drv.is_null() {
                            String::new()
                        } else {
                            cstr_or_empty((*drv).name)
                        },
                        driver_longname: if drv.is_null() {
                            String::new()
                        } else {
                            cstr_or_empty((*drv).longname)
                        },
                        channels,
                    });
                }
                if !list.is_null() {
                    g_slist_free(list);
                }
            }
        }

        if devices.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No sigrok-supported logic analyzers found",
                "No devices were detected. Connect a supported logic analyzer and retry, \
                 or use 'iottack logic-analyser capture --driver demo' to test with a \
                 simulated device.",
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        result.add(PluginFinding::new(
            Severity::Info,
            format!("{} logic analyzer(s) detected", devices.len()),
            format!("Use 'iottack logic-analyser capture --driver <DRIVER>' to start a capture."),
        ));

        for dev in &devices {
            let ch_summary = if dev.channels.is_empty() {
                "none".to_string()
            } else {
                dev.channels
                    .iter()
                    .map(|(name, enabled)| {
                        if *enabled {
                            name.clone()
                        } else {
                            format!("{name} (disabled)")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            let description = format!(
                "Driver:     {} ({})\n  \
                 Vendor:     {}\n  \
                 Model:      {}\n  \
                 Version:    {}\n  \
                 Serial:     {}\n  \
                 Connection: {}\n  \
                 Channels:   {} - {}",
                dev.driver_name,
                dev.driver_longname,
                dev.vendor,
                dev.model,
                dev.version,
                if dev.serial.is_empty() {
                    "n/a"
                } else {
                    &dev.serial
                },
                if dev.connid.is_empty() {
                    "n/a"
                } else {
                    &dev.connid
                },
                dev.channels.len(),
                ch_summary,
            );

            let evidence = format!(
                "vendor={}, model={}, version={}, serial={}, connection={}, \
                 driver={}, channels=[{}]",
                dev.vendor,
                dev.model,
                dev.version,
                dev.serial,
                dev.connid,
                dev.driver_name,
                dev.channels
                    .iter()
                    .map(|(n, e)| format!("{n}:{}", if *e { "on" } else { "off" }))
                    .collect::<Vec<_>>()
                    .join(","),
            );

            result.add(
                PluginFinding::new(
                    Severity::Info,
                    format!("{} {} (driver: {})", dev.vendor, dev.model, dev.driver_name,),
                    description,
                )
                .with_evidence(evidence),
            );
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(DevicePlugin::new()) as Box<dyn crate::Plugin>)
}
