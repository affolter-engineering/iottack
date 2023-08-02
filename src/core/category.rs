use serde::{Deserialize, Serialize};
use std::fmt;

/// Broad protocol/technology family for a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    /// Physical bus interfaces: UART, SPI, I2C, CAN, JTAG, SWD
    Physical,
    /// Short-range wireless: BLE, ZigBee, Z-Wave, 433 MHz
    Radio,
    /// IP-layer protocols: CoAP, MQTT, AMQP, HTTP, nanomsg, etc.
    Network,
    /// Firmware extraction, analysis, modification
    Firmware,
    /// Cryptographic weaknesses and key material
    Cryptography,
    /// Host-level enumeration and disclosure
    Host,
}

/// Implement `Display` for `Category` to provide a lowercase string representation.
impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Physical => "physical",
            Self::Radio => "radio",
            Self::Network => "network",
            Self::Firmware => "firmware",
            Self::Cryptography => "cryptography",
            Self::Host => "host",
        };
        write!(f, "{s}")
    }
}
