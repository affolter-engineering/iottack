use crate::core::{
    Plugin, PluginConfig, PluginFinding, PluginMeta, PluginResult, PluginStatus, Severity,
};
use crate::plugin_meta;
use anyhow::Result;
use ftdi_nusb::{
    blocking::FtdiDevice,
    device_info::find_devices,
    types::{ChipType, Interface},
};

const FTDI_VID: u16 = 0x0403;

/// Common FTDI product IDs to probe during enumeration.
const KNOWN_PIDS: &[u16] = &[
    0x6001, // FT8U232AM / FT232BM / FT232R
    0x6010, // FT2232C / FT2232H
    0x6011, // FT4232H
    0x6014, // FT232H
    0x6015, // FT230X / FT231X / FT234XD
];

pub struct DevicePlugin;

impl DevicePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DevicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for DevicePlugin {
    fn meta(&self) -> PluginMeta {
        plugin_meta!(
            summary: "List FTDI adapters connected to this host",
            description: "Probes all common FTDI USB product IDs (FT232R, FT2232H, FT4232H, \
                          FT232H, FT230X) and reports each adapter with its chip type, unique \
                          chip ID, EEPROM strings (manufacturer, product, serial) and MPSSE \
                          capability. On Linux, requires the udev rule for non-root access: \
                          SUBSYSTEM==\"usb\", ATTR{idVendor}==\"0403\", MODE=\"0666\"",
            needs_root: false,
        )
    }

    fn execute(&mut self) -> Result<PluginResult> {
        let mut result = PluginResult::new(self.meta().name);

        struct Entry {
            vid: u16,
            pid: u16,
            chip: &'static str,
            chip_id: Option<u32>,
            manufacturer: String,
            product: String,
            serial: String,
            mpsse: &'static str,
        }

        let mut found: Vec<Entry> = Vec::new();
        let mut access_errors: Vec<String> = Vec::new();

        for &pid in KNOWN_PIDS {
            let device_list = match find_devices(FTDI_VID, pid) {
                Ok(list) => list,
                Err(_) => continue,
            };

            for dev_info in device_list {
                let vid = dev_info.vendor_id();
                let pid_found = dev_info.product_id();

                let mut dev = match FtdiDevice::from_device_info(dev_info, Interface::A) {
                    Ok(d) => d,
                    Err(e) => {
                        access_errors.push(format!(
                            "{vid:04x}:{pid_found:04x}: {e}"
                        ));
                        continue;
                    }
                };

                let chip_type = dev.chip_type();
                let chip_id = dev.read_chipid().ok();

                let (manufacturer, product, serial) = match dev.eeprom_decode() {
                    Ok(_) => {
                        let (m, p, s) = dev.eeprom().strings();
                        (
                            m.unwrap_or("").to_string(),
                            p.unwrap_or("").to_string(),
                            s.unwrap_or("").to_string(),
                        )
                    }
                    Err(_) => (String::new(), String::new(), String::new()),
                };

                found.push(Entry {
                    vid,
                    pid: pid_found,
                    chip: chip_label(chip_type),
                    chip_id,
                    manufacturer,
                    product,
                    serial,
                    mpsse: mpsse_channels(chip_type),
                });
            }
        }

        if found.is_empty() && access_errors.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                "No FTDI adapters found",
                "No FTDI devices were detected (VID 0x0403). Connect an adapter and retry.\n\
                 On Linux, ensure the udev rule is in place:\n\
                 echo 'SUBSYSTEM==\"usb\", ATTR{{idVendor}}==\"0403\", MODE=\"0666\"' \\\n\
                 | sudo tee /etc/udev/rules.d/99-ftdi.rules && sudo udevadm control --reload",
            ));
            result.finish(PluginStatus::Pass);
            return Ok(result);
        }

        if !found.is_empty() {
            result.add(PluginFinding::new(
                Severity::Info,
                format!("{} FTDI adapter(s) detected", found.len()),
                "Use 'iottack i2c scan' or 'iottack i2c read' for I2C operations. \
                 Pass --pid <PID> on those plugins to select a specific adapter.",
            ));
        }

        for entry in &found {
            let chip_id_str = entry
                .chip_id
                .map(|id| format!("{id:08x}"))
                .unwrap_or_else(|| "n/a".to_string());

            let description = format!(
                "USB:          {:04x}:{:04x}\n  \
                 Chip:         {}\n  \
                 Chip ID:      {chip_id_str}\n  \
                 Manufacturer: {}\n  \
                 Product:      {}\n  \
                 Serial:       {}\n  \
                 MPSSE:        {}",
                entry.vid,
                entry.pid,
                entry.chip,
                if entry.manufacturer.is_empty() { "n/a" } else { &entry.manufacturer },
                if entry.product.is_empty() { "n/a" } else { &entry.product },
                if entry.serial.is_empty() { "n/a" } else { &entry.serial },
                entry.mpsse,
            );

            let evidence = format!(
                "vid={:04x} pid={:04x} chip={} chip_id={chip_id_str} serial={}",
                entry.vid,
                entry.pid,
                entry.chip,
                if entry.serial.is_empty() { "n/a" } else { &entry.serial },
            );

            let title = if entry.product.is_empty() {
                format!("{} ({:04x}:{:04x})", entry.chip, entry.vid, entry.pid)
            } else {
                format!("{} — {}", entry.chip, entry.product)
            };

            result.add(
                PluginFinding::new(Severity::Info, title, description)
                    .with_evidence(evidence),
            );
        }

        for err in &access_errors {
            result.add(PluginFinding::new(
                Severity::Info,
                "FTDI device access error",
                format!(
                    "{err}\n\n\
                     Apply the udev rule or run as root:\n\
                     echo 'SUBSYSTEM==\"usb\", ATTR{{idVendor}}==\"0403\", MODE=\"0666\"' \\\n\
                     | sudo tee /etc/udev/rules.d/99-ftdi.rules && sudo udevadm control --reload"
                ),
            ));
        }

        result.finish(PluginStatus::Pass);
        Ok(result)
    }
}

fn chip_label(ct: ChipType) -> &'static str {
    match ct {
        ChipType::Am => "FT8U232AM",
        ChipType::Bm => "FT232BM / FT245BM",
        ChipType::Ft2232C => "FT2232C / FT2232D / FT2232L",
        ChipType::Ft232R => "FT232R / FT245R",
        ChipType::Ft2232H => "FT2232H",
        ChipType::Ft4232H => "FT4232H",
        ChipType::Ft232H => "FT232H",
        ChipType::Ft230X => "FT230X / FT231X / FT234XD",
        _ => "Unknown",
    }
}

fn mpsse_channels(ct: ChipType) -> &'static str {
    match ct {
        ChipType::Ft2232C => "A, B (12 MHz)",
        ChipType::Ft2232H => "A, B (30 MHz Hi-Speed)",
        ChipType::Ft4232H => "A, B (30 MHz Hi-Speed); C, D UART only",
        ChipType::Ft232H => "A (30 MHz Hi-Speed)",
        _ => "none",
    }
}

inventory::submit! {
    crate::PluginFactory(|| Box::new(DevicePlugin::new()) as Box<dyn crate::Plugin>)
}
