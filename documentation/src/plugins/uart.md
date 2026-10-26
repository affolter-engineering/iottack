# UART

UART (Universal Asynchronous Receiver-Transmitter) is the most common
low-level serial interface found on embedded hardware. Almost every IoT device
exposes a UART header on its PCB. It is used for boot log output, firmware
flashing and factory debugging.

## How UART works

UART transmits data one bit at a time over two wires:

- TX (transmit)
- RX (receive).

The two sides agree on a set of parameters before communication:

| Parameter | Typical IoT value | Notes |
|-----------|------------------|-------|
| Baud rate | 115200 | Also common: 9600, 57600, 38400, 19200 |
| Data bits | 8 | Almost always 8 |
| Parity | None | N - no parity bit |
| Stop bits | 1 | 8N1 is the de-facto standard |
| Flow control | None | Hardware (RTS/CTS) rarely used on IoT |

A single character frame looks like:

```text
IDLE  START  D0  D1  D2  D3  D4  D5  D6  D7  STOP  IDLE
HIGH    LOW  ...data bits (LSB first)...       HIGH  HIGH
```

The line is held HIGH when idle. A START bit (LOW) signals the beginning of a
frame; the receiver samples each data bit at the agreed baud rate; a STOP bit
(HIGH) closes the frame. Because there is no clock line, both sides must be
configured to the same baud rate before they can communicate that making baud
rate discovery the first step in any UART assessment.

## Physical access

Accessing a UART interface requires:

1. **Locating the header**: look for unpopulated 3-5 pin headers near the
   main SoC on the PCB. Common pinouts are GND/TX/RX/VCC (3.3 V or 5 V).
   A logic analyzer or oscilloscope can confirm which pin is TX by observing
   activity during boot.
2. **Matching voltage**: most modern SoCs use 3.3 V logic. Connecting a 5 V
   adapter directly can damage the device. Always verify with a multimeter.
3. **USB-to-UART adapter**: a CP2102, CH340 or FTDI adapter is required to
   connect the device to a host PC. Connect device TX to adapter RX and vice
   versa; share a common ground.

## Attack surface

UART is extremely high-value for hardware security assessments:

- **Boot log disclosure**: the bootloader and kernel print extensive diagnostic
  output including memory map, partition layout, kernel version and mount
  points before any authentication is required.
- **U-Boot shell**: if the bootloader is not locked, pressing a key during the
  countdown drops into a U-Boot prompt with full memory read/write access.
- **Root shell**: many devices drop directly to a root shell on the UART
  console with no login prompt. No credentials required.
- **Firmware recovery**: UART is typically used for factory re-flashing,
  meaning it can be used to extract or replace firmware.
- **Baud rate unknown**: the baud rate is not transmitted in-band. If it is not
  printed on the PCB silkscreen, it must be discovered by scanning common
  values or measuring the bit period with a logic analyzer.

## Plugins

| Plugin | Command | Summary |
|--------|---------|---------|
| [uart port-scan](./uart/port-scan.md) | `iottack uart port-scan` | Discover serial ports available on the host |
| [uart baud-scan](./uart/baud-scan.md) | `iottack uart baud-scan` | Probe common baud rates to find the active configuration |
| [uart shell-detect](./uart/shell-detect.md) | `iottack uart shell-detect` | Detect interactive shell or login prompt on the UART interface |
| [uart terminal](./uart/terminal.md) | `iottack uart terminal` | Open an interactive terminal session over UART |
| [uart fuzz](./uart/fuzz.md) | `iottack uart fuzz` | Send malformed payloads and report anomalous responses |

## Typical workflow

1. **Find the port**: list serial adapters visible to the OS.

   ```sh
   iottack uart port-scan
   ```

2. **Find the baud rate**: scan common rates and capture the first output.

   ```sh
   iottack uart baud-scan --port /dev/ttyUSB0
   ```

3. **Detect the console type**: check whether the port exposes a shell or
   login prompt.

   ```sh
   iottack uart shell-detect --port /dev/ttyUSB0 --baud 115200
   ```

4. **Interact**: open an interactive terminal to explore the device.

   ```sh
   iottack uart terminal --port /dev/ttyUSB0 --baud 115200
   ```
