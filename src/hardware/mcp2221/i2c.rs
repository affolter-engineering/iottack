use anyhow::{anyhow, Result};
use nusb::{
    transfer::{Buffer, In, Interrupt, Out},
    Endpoint, Interface, MaybeFuture,
};
use std::time::Duration;

const MCP2221_VID: u16 = 0x04D8;
const MCP2221_PID: u16 = 0x00DD;
const HID_IFACE: u8 = 2;
const EP_OUT: u8 = 0x03;
const EP_IN: u8 = 0x83;
const REPORT_SIZE: usize = 64;
const TIMEOUT: Duration = Duration::from_millis(500);

const CMD_I2C_WRITE: u8 = 0x90;
const CMD_STATUS_SET: u8 = 0x10;
const CANCEL_TRANSFER: u8 = 0x10;
const SET_BUS_SPEED: u8 = 0x20;

// I2C engine state machine values in STATUS response byte[8] (I2C_POLL_RESP_STATUS).
// WRITE NACK (0x25) persists until cancelled — unlike READ NACK which
// auto-transitions before the first poll arrives.  0x44 (WRITEDATA_TOUT) is
// the uninitialized engine state before the first I2C_speed call.
const I2C_ST_IDLE: u8 = 0x00;             // idle / transfer complete (ACK)
const I2C_ST_NACK_STOP: u8 = 0x25;        // address not acknowledged
const I2C_ST_WRADDRL_TOUT: u8 = 0x23;     // timeout sending address
const I2C_ST_WRITEDATA_TOUT: u8 = 0x44;   // data-phase timeout / uninitialized engine
const I2C_ST_STOP_TOUT: u8 = 0x62;        // bus stuck (SCL/SDA held low)

/// MCP2221A HID I2C session.
///
/// Communicates with the MCP2221A over its USB HID interface (interface 2)
/// using 64-byte interrupt transfers. The kernel `usbhid` driver is detached
/// for the duration of the session and re-attached on drop.
pub struct Mcp2221I2c {
    _iface: Interface,
    ep_out: Endpoint<Interrupt, Out>,
    ep_in: Endpoint<Interrupt, In>,
}

impl Mcp2221I2c {
    /// Open the first MCP2221/MCP2221A found, detach the kernel HID driver,
    /// claim the HID interface and initialize the I2C engine at 100 kHz.
    ///
    /// The MCP2221A I2C engine is in an uninitialized state (0x44) after USB
    /// enumeration until the speed is set.  This call sets it to 100 kHz,
    /// mirroring what EasyMCP2221 does in `__init__`.
    pub fn open() -> Result<Self> {
        let dev_info = nusb::list_devices()
            .wait()
            .map_err(|e| anyhow!("USB enumeration failed: {e}"))?
            .find(|d| d.vendor_id() == MCP2221_VID && d.product_id() == MCP2221_PID)
            .ok_or_else(|| {
                anyhow!(
                    "MCP2221 not found (04d8:00dd). Connect the adapter and ensure the udev \
                     rules are active"
                )
            })?;

        let device = dev_info
            .open()
            .wait()
            .map_err(|e| anyhow!("failed to open MCP2221: {e}"))?;

        let iface = device
            .detach_and_claim_interface(HID_IFACE)
            .wait()
            .map_err(|e| anyhow!("failed to claim MCP2221 HID interface: {e}"))?;

        let ep_out = iface
            .endpoint::<Interrupt, Out>(EP_OUT)
            .map_err(|e| anyhow!("cannot open interrupt OUT endpoint 0x{EP_OUT:02x}: {e}"))?;

        let ep_in = iface
            .endpoint::<Interrupt, In>(EP_IN)
            .map_err(|e| anyhow!("cannot open interrupt IN endpoint 0x{EP_IN:02x}: {e}"))?;

        let mut inst = Self { _iface: iface, ep_out, ep_in };
        inst.init_i2c(100_000)?;
        Ok(inst)
    }

    /// Probe a 7-bit I2C address by issuing a 1-byte write and checking for ACK.
    ///
    /// `CMD_I2C_WRITE` with one dummy byte is used: on WRITE, the NACK state
    /// (0x25) persists in the STATUS register until cancelled, so STATUS polling
    /// at ~2 ms round-trip reliably distinguishes ACK (0x00 IDLE) from NACK
    /// (0x25).  `CMD_I2C_READ` NACK auto-transitions to 0x52 before the first
    /// poll, making it unreliable at our USB latency.
    ///
    /// Returns `true` if the address byte was ACKed.
    pub fn probe(&mut self, addr: u8) -> Result<bool> {
        let mut cmd = [0u8; REPORT_SIZE];
        cmd[0] = CMD_I2C_WRITE;
        cmd[1] = 1;         // length LSB: 1 data byte
        cmd[2] = 0;         // length MSB
        cmd[3] = addr << 1; // 7-bit address with write bit (bit 0 = 0)
        cmd[4] = 0x00;      // dummy data byte

        self.send(&cmd)?;
        let init = self.recv()?;
        tracing::debug!(
            addr = format!("0x{addr:02x}"),
            resp1 = format!("0x{:02x}", init[1]),
            "CMD_I2C_WRITE initial response"
        );

        if init[1] != 0x00 {
            // Command rejected — bus busy from previous incomplete operation.
            self.cancel().ok();
            return Ok(false);
        }

        // Poll STATUS (resp[8] = I2C_POLL_RESP_STATUS) until terminal state.
        // 0x25 (NACK) persists until cancel; 0x00 (IDLE) = write ACKed.
        let mut acked = false;
        let mut last_state = 0u8;
        for i in 0..20 {
            let mut status = [0u8; REPORT_SIZE];
            status[0] = CMD_STATUS_SET;
            self.send(&status)?;
            let resp = self.recv()?;
            last_state = resp[8];

            tracing::trace!(
                addr = format!("0x{addr:02x}"),
                poll = i,
                state = format!("0x{last_state:02x}"),
                "STATUS poll"
            );

            match last_state {
                I2C_ST_IDLE => {
                    acked = true;
                    break;
                }
                I2C_ST_NACK_STOP | I2C_ST_WRADDRL_TOUT | I2C_ST_WRITEDATA_TOUT
                | I2C_ST_STOP_TOUT => break,
                _ => {}
            }
        }

        if !acked {
            tracing::debug!(
                addr = format!("0x{addr:02x}"),
                last_state = format!("0x{last_state:02x}"),
                "probe: NACK or timeout"
            );
        }

        self.cancel().ok();
        Ok(acked)
    }

    /// Initialise the I2C engine and set the bus clock.
    ///
    /// The MCP2221A I2C engine must have its speed set before first use;
    /// without this the engine stays in the uninitialized state (0x44) and
    /// ignores write/read commands.  Mirrors EasyMCP2221's `I2C_speed()`.
    fn init_i2c(&mut self, hz: u32) -> Result<()> {
        // divider = round(12 MHz / hz) - 2  (clamped to 0-255)
        let divider = ((12_000_000u32 + hz / 2) / hz).saturating_sub(2).min(255) as u8;

        let mut cmd = [0u8; REPORT_SIZE];
        cmd[0] = CMD_STATUS_SET;
        cmd[3] = SET_BUS_SPEED; // sub-command: set I2C clock divider now
        cmd[4] = divider;

        self.send(&cmd)?;
        let resp = self.recv()?;

        // resp[3] echoes the sub-command on success (0x20), or 0x00 on failure.
        if resp[3] != SET_BUS_SPEED {
            return Err(anyhow!(
                "MCP2221 I2C speed init failed (resp[3]=0x{:02x}). \
                 Is the bus busy from a previous session?",
                resp[3]
            ));
        }

        tracing::debug!(hz, divider, "MCP2221 I2C speed set");
        Ok(())
    }

    /// Send a 64-byte HID report to the device.
    fn send(&mut self, data: &[u8; REPORT_SIZE]) -> Result<()> {
        self.ep_out
            .transfer_blocking(Buffer::from(data.as_slice()), TIMEOUT)
            .into_result()
            .map(|_| ())
            .map_err(|e| anyhow!("MCP2221 write failed: {e}"))
    }

    /// Receive a 64-byte HID report from the device.
    fn recv(&mut self) -> Result<Buffer> {
        self.ep_in
            .transfer_blocking(Buffer::new(REPORT_SIZE), TIMEOUT)
            .into_result()
            .map_err(|e| anyhow!("MCP2221 read failed: {e}"))
    }

    /// Cancel any in-progress I2C transfer and wait for the engine to reach IDLE.
    ///
    /// After cancel the engine transitions through STOP (0x60) before reaching
    /// IDLE (0x00); polling is needed before issuing the next command.
    fn cancel(&mut self) -> Result<()> {
        let mut cmd = [0u8; REPORT_SIZE];
        cmd[0] = CMD_STATUS_SET;
        cmd[2] = CANCEL_TRANSFER;
        self.send(&cmd)?;
        self.recv()?;

        // Wait for engine to settle at IDLE (transitions through STOP first).
        for _ in 0..10 {
            let mut status = [0u8; REPORT_SIZE];
            status[0] = CMD_STATUS_SET;
            self.send(&status)?;
            let resp = self.recv()?;
            if resp[8] == I2C_ST_IDLE {
                break;
            }
        }
        Ok(())
    }
}
