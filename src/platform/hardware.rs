/// Known USB testing and IoT hardware tools: (vendor_id, product_id, label).
pub const KNOWN_TOOLS: &[(&str, &str, &str)] = &[
    // Testing/exploitation platforms
    ("0483", "ba20", "Expliot Bus Auditor"),
    ("1d50", "608c", "GreatFET One (Great Scott Gadgets)"),
    ("1d50", "6002", "HackRF One"),
    ("1d50", "605b", "YARD Stick One"),
    ("1d50", "6018", "Glasgow Interface Explorer"),
    ("0483", "5740", "Flipper Zero"),
    ("9ac4", "4b8f", "Proxmark3"),
    ("16d0", "04b2", "Chameleon Mini (RFID emulator)"),
    // Bus interface tools
    ("04d8", "fb00", "Bus Pirate v3"),
    ("04d8", "fb01", "Bus Pirate v4"),
    // Debug probes
    ("0d28", "0204", "ARM DAPLink debug probe"),
    ("0483", "3748", "ST-Link/V2"),
    ("0483", "374b", "ST-Link/V2-1"),
    ("0483", "374e", "ST-Link/V3"),
    ("1366", "0101", "Segger J-Link"),
    ("1366", "0105", "Segger J-Link OB"),
    ("03eb", "2141", "Atmel-ICE"),
    ("2e8a", "000c", "Raspberry Pi Picoprobe"),
    // ZigBee/802.15.4/Thread/BLE
    ("1915", "521a", "nRF52840 Dongle (ZigBee/BLE)"),
    ("0451", "16a8", "TI CC2531 ZigBee USB Dongle"),
    ("0451", "16ae", "TI CC2531 USB Dongle"),
    ("0451", "bef3", "TI CC2652 LaunchPad"),
    ("10c4", "8a5e", "Sonoff Zigbee 3.0 USB Dongle Plus"),
    // Espressif
    ("303a", "1001", "Espressif USB JTAG/serial debug unit (ESP32-S2/S3/C3/C6)"),
    ("303a", "0002", "Espressif ESP32-S2 native USB"),
    // USB-serial bridges
    ("0403", "6001", "FTDI FT232 USB-Serial"),
    ("0403", "6010", "FTDI FT2232 Dual UART/FIFO"),
    ("0403", "6011", "FTDI FT4232 Quad UART"),
    ("0403", "6014", "FTDI FT232H"),
    ("0403", "6015", "FTDI FT231X USB-Serial"),
    ("10c4", "ea60", "CP210x USB-Serial"),
    ("10c4", "ea70", "CP2105 Dual USB-Serial"),
    ("1a86", "7523", "CH340/CH341 USB-Serial"),
    ("1a86", "55d4", "CH343 USB-Serial"),
    ("04b4", "f13b", "Cypress USB-Serial"),
    // SDR
    ("0bda", "2838", "RTL-SDR (DVB-T dongle)"),
    ("0bda", "2832", "RTL-SDR v2"),
    ("04b4", "00f1", "LimeSDR"),
    ("0456", "b673", "ADALM-PLUTO SDR"),
    // Wi-Fi
    ("0bda", "8187", "Realtek RTL8187 (802.11b/g)"),
    ("148f", "7601", "Ralink RT7601 (802.11n)"),
    ("148f", "5370", "Ralink RT5370 (802.11n)"),
    ("0cf3", "9271", "Atheros AR9271 (802.11n)"),
];

/// Return the human-readable label for a USB device, if it is in the known-tools table.
pub fn match_known_tool(vendor_id: &str, product_id: &str) -> Option<&'static str> {
    KNOWN_TOOLS
        .iter()
        .find(|(v, p, _)| *v == vendor_id && *p == product_id)
        .map(|(_, _, label)| *label)
}
