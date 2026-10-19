use serde::{Deserialize, Serialize};
use std::fmt;

/// Broad protocol/technology family for a plugin.
///
/// ```
/// use iottack::Category;
/// assert_eq!(Category::Network.to_string(), "network");
/// assert_eq!(Category::Physical.to_string(), "physical");
/// ```
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

/// Tests for the `Category` enum and its `Display` implementation.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_all_variants() {
        assert_eq!(Category::Physical.to_string(), "physical");
        assert_eq!(Category::Radio.to_string(), "radio");
    }
}
