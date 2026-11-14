# 1-Wire plugins

1-Wire (Dallas/Maxim) is a single-wire serial bus used for temperature sensors,
iButton authentication tokens, EEPROMs and other low-speed peripherals. Each
device carries a unique 64-bit ROM code (8-bit family & 48-bit serial & 8-bit
CRC) that serves as its address. Multiple devices share a single data line using
a master-slave open-drain protocol.

The protocol has no authentication or encryption. Any master that can reach the
bus can enumerate all ROM codes, read sensor data and in some cases write to
configuration or EEPROM storage. iButton tokens (DS1990A, DS2401) are used as
physical access credentials in many industrial and building-automation systems.
Their 48-bit serial numbers can be read in milliseconds and are trivially
cloneable.

## Hardware requirement

All 1-Wire plugins use the **FTDI UART TX/RX loopback method**. This works on
any FTDI chip (FT232R, FT232H, FT2232H, FT4232H) and requires no special
adapter beyond the chip itself.

### Wiring generic

Connect TX and RX together to the 1-Wire DQ line and add a 4.7 kOhm pull-up
resistor from DQ to VCC (3.3 V or 5 V depending on target):

```text
FTDI TX ──┬──── DQ (1-Wire bus)
FTDI RX ──┘        │
                  4.7 kOhm
                   │
                  VCC (3.3 V or 5 V)
```

The TX line drives the bus low. Because TX and RX are shorted, RX reads back
the actual bus level (open-drain pull-up for 1, TX-driven low for 0), giving
exact timing via the FTDI hardware UART engine.

### FT4232H

The FT4232H has four independent UART channels (A-D). Each channel exposes a
TX and RX pin on its `xDBUS` header. Use any channel. The example below uses
channel A.

- **FT4232H channel pin names**

| Channel | TX pin | RX pin |
| ------- | ------ | ------ |
| A | ADBUS0 (TXD) | ADBUS1 (RXD) |
| B | BDBUS0 (TXD) | BDBUS1 (RXD) |
| C | CDBUS0 (TXD) | CDBUS1 (RXD) |
| D | DDBUS0 (TXD) | DDBUS1 (RXD) |

- **DS18B20 pin-out (TO-92, flat side facing you)**

```text
  DS18B20
  ┌───────┐
  │ 1 2 3 │
  └───────┘
    │ │ └── VDD  -> 3.3 V or 5 V
    │ └──── DQ   -> data line
    └────── GND  -> ground
```

- **Full connection diagram (channel A, 3.3 V)**

```text
FT4232H                        DS18B20
─────────                      ───────
ADBUS0 (TXD) ──┬────────────── DQ  (pin 2)
ADBUS1 (RXD) ──┘     │
                   4.7 kOhm
                     │
3.3 V ───────────────┴──────── VDD (pin 3)
GND  ───────────────────────── GND (pin 1)
```

The 4.7 kOhm resistor is mandatory. Without it the open-drain bus cannot return
to logic high between slots and every bit reads back as 0.

DS18B20 is 5 V tolerant. If the target system runs at 5 V, replace the 3.3 V
rail with 5 V. The FT4232H I/O is 3.3 V logic. The DS18B20 input threshold is
well below that, so a 5 V pull-up with 3.3 V-driven TX still works correctly.

**Run the scan on channel A:**

```sh
iottack onewire scan --channel A --temp
```

### Linux UDEV rule

Add the following rule so the FTDI device is accessible without root:

```text
SUBSYSTEM=="usb", ATTR{idVendor}=="0403", MODE="0666"
```

Place it in `/etc/udev/rules.d/99-ftdi.rules` and run `udevadm control --reload-rules`.

## Plugins

| Plugin | Command | Purpose |
| ------ | ------- | ------- |
| [scan](./onewire/scan.md) | `iottack onewire scan` | Enumerate all 1-Wire device ROM codes on the bus and report family type and security relevance |

## Severity model

| Finding | Severity | Rationale |
| ------- | -------- | --------- |
| DS2401 iButton (or DS1990A) | **Low** | Used as physical-access credential; trivially cloneable |
| DS2431/DS28EC20 EEPROM | **Medium** | May store configuration or key material |
| DS18B20/DS1822 temperature | **Info** | Presence noted; temperature data is not sensitive |
| Other known family | **Info** | Device enumerated; assess per deployment |
| Unknown family | **Low** | Unrecognized family byte warrants manual inspection |
