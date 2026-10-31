# FTDI MPSSE Adapter

[FTDI](https://ftdichip.com/) USB-to-serial chips are used throughout `iottack`
as a generic hardware bridge between the host and embedded targets.
The FT232H, FT2232H and FT4232H all expose the **MPSSE** (Multi-Protocol
Synchronous Serial Engine), which allows a single USB device to speak I2C, SPI,
JTAG, SWD or plain UART depending on configuration.

## Supported chips

| Chip | Channels | MPSSE channels | USB PID |
|------|----------|----------------|---------|
| FT232R | 1 | - | `0x6001` |
| FT232H | 1 | 1 (A) | `0x6014` |
| FT2232H | 2 | 2 (A, B) | `0x6010` |
| FT4232H | 4 | 2 (A, B) | `0x6011` |

All chips share vendor ID `0x0403`. Only channels **A** and **B** have an MPSSE
engine. Channels C and D on the FT4232H are UART/bit-bang only.

## Wiring

### I2C

```text
Adapter        Target
AD0      ->    SCL (plus 4.7 kOhm pull-up to VCC)
AD1+AD2  <->   SDA (AD1 and AD2 shorted. Plus 4.7 kOhm pull-up to VCC)
GND      <->   GND
```

AD1 is the write path and AD2 is the read path for SDA. Both pins must be
shorted together because the FT4232H has no open-drain output mode.

### SPI

```text
Adapter       Target
AD0     ->    SCLK
AD1     ->    MOSI
AD2     <-    MISO
AD3     ->    CS# (active low)
GND     <->   GND
```

### JTAG

```text
Adapter       Target
AD0     ->    TCK
AD1     ->    TDI
AD2     <-    TDO
AD3     ->    TMS
AD7     ->    nSRST (optional)
GND     <->   GND
```

### SWD

```text
Adapter        Target
AD0      ->    SWCLK
AD1+AD2  <->   SWDIO (220-470 Ohm on AD1 -> SWDIO prevents contention)
AD4      ->    nRESET (optional)
GND      <->   GND
```

## Linux setup (udev)

Without a udev rule the kernel will not grant regular users access to the USB
device. Add the following rule once:

```sh
echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="0403", MODE="0666"' \
  | sudo tee /etc/udev/rules.d/99-ftdi.rules
sudo udevadm control --reload
sudo udevadm trigger
```

Reconnect the adapter after reloading.

## Clock frequencies

| Mode | Typical | Maximum |
|------|---------|---------|
| I2C standard | 100 kHz | 100 kHz |
| I2C fast | 400 kHz | 400 kHz |
| SPI | 1 MHz | 30 MHz |
| JTAG | 1-10 MHz | 30 MHz |
