use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

/// A USB device visible in the host's sysfs tree that has an associated
/// TTY character device node.
#[derive(Debug, Clone)]
pub struct UsbDevice {
    /// TTY node, e.g., `/dev/ttyUSB0`.
    pub tty_node: String,
    /// Vendor:product ID string, e.g., `"0403:6001"`.
    pub id: String,
    pub manufacturer: String,
    pub product: String,
    /// Absolute sysfs path for the USB device.
    pub sysfs_path: PathBuf,
}

fn read_attr(base: &Path, attr: &str) -> Option<String> {
    fs::read_to_string(base.join(attr))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Build a map of tty_name -> resolved sysfs path by following
/// `/sys/class/tty/<name>/device` symlinks.
fn tty_usb_map() -> HashMap<String, PathBuf> {
    let mut map = HashMap::new();
    let tty_class = Path::new("/sys/class/tty");
    let Ok(rd) = fs::read_dir(tty_class) else {
        return map;
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let link = entry.path().join("device");
        if let Ok(target) = fs::canonicalize(&link) {
            let name = entry.file_name().to_string_lossy().into_owned();
            map.insert(name, target);
        }
    }
    map
}

/// Enumerate USB devices attached to the host via `/sys/bus/usb/devices/`.
/// Returns only devices that have a TTY node associated with them.
pub fn enumerate_usb_tty_devices() -> Vec<UsbDevice> {
    let mut devices = Vec::new();
    let tty_map = tty_usb_map();
    let usb_root = Path::new("/sys/bus/usb/devices");

    let Ok(rd) = fs::read_dir(usb_root) else {
        return devices;
    };

    for entry in rd.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();

        // Skip interface entries (contain ':') and root hubs (named "usb*").
        if name.contains(':') || name.starts_with("usb") {
            continue;
        }

        let dev_path = entry.path();
        let Some(vendor_id) = read_attr(&dev_path, "idVendor") else {
            continue;
        };
        let Some(product_id) = read_attr(&dev_path, "idProduct") else {
            continue;
        };

        let product = read_attr(&dev_path, "product").unwrap_or_else(|| "Unknown".into());

        // Skip root hubs that slipped through.
        if product.to_lowercase().contains("root hub") {
            continue;
        }

        let manufacturer = read_attr(&dev_path, "manufacturer").unwrap_or_else(|| "Unknown".into());

        // Resolve the sysfs path so we can match it against TTY symlink targets.
        let Ok(resolved) = fs::canonicalize(&dev_path) else {
            continue;
        };

        for (tty_name, tty_target) in &tty_map {
            if tty_target.starts_with(&resolved) {
                devices.push(UsbDevice {
                    tty_node: format!("/dev/{tty_name}"),
                    id: format!("{vendor_id}:{product_id}"),
                    manufacturer: manufacturer.clone(),
                    product: product.clone(),
                    sysfs_path: resolved.clone(),
                });
            }
        }
    }

    devices.sort_by(|a, b| a.tty_node.cmp(&b.tty_node));
    devices
}

/// Return true if a USB device with `vendor_id:product_id` is currently
/// attached, regardless of whether it has a TTY node.
pub fn usb_device_present(vendor_id: &str, product_id: &str) -> bool {
    let usb_root = Path::new("/sys/bus/usb/devices");
    let Ok(rd) = fs::read_dir(usb_root) else {
        return false;
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let p = entry.path();
        let vid = read_attr(&p, "idVendor").unwrap_or_default();
        let pid = read_attr(&p, "idProduct").unwrap_or_default();
        if vid == vendor_id && pid == product_id {
            return true;
        }
    }
    false
}

/// Read a single-line file from `/proc/sys/kernel/<name>`.
pub fn kernel_attr(name: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/sys/kernel/{name}"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Parse `/etc/os-release` and return the value for `key` (without quotes).
pub fn os_release_field(key: &str) -> Option<String> {
    let raw = fs::read_to_string("/etc/os-release").ok()?;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}=")) {
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}

/// Return the effective UID of the running process via `/proc/self/status`.
pub fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        // "Uid:	1000	1000	1000	1000"  (real, effective, saved, filesystem)
        if let Some(rest) = line.strip_prefix("Uid:") {
            let mut parts = rest.split_whitespace();
            parts.next(); // real uid
            return parts.next()?.parse().ok(); // effective uid
        }
    }
    None
}
