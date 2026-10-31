# i2c scan

Probe all 112 valid 7-bit I2C addresses and report every device that responds
with an ACK.

## Requirements

An FTDI MPSSE adapter (FT232H, FT2232H or FT4232H) connected to the I2C bus.
See [FTDI adapter wiring](../hardware/ftdi.md#i2c) for the exact pin connections
and the required udev rule.

## Usage

```sh
iottack i2c i2c-scan [OPTIONS]
```

## Description

For each address in the range **0x08-0x77** the plugin sends a zero-byte I2C
write (START + address + W + STOP) and checks for ACK. Reserved address ranges
(0x00–0x07 general call / high-speed codes, 0x78–0x7F 10-bit addressing) are
skipped.

Addresses that respond are reported at **Medium** severity together with a hint
about common devices that use that address range.

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--channel <CHANNEL>` | `-c` | `A` | FTDI channel to use — must be A or B (MPSSE-capable) |
| `--vid <HEX>` | — | `0403` | USB vendor ID in hex |
| `--pid <HEX>` | — | `6011` | USB product ID in hex (6001=FT232R, 6010=FT2232H, 6011=FT4232H, 6014=FT232H) |
| `--clock-hz <HZ>` | — | `100000` | I2C clock frequency in Hz |
| `--output <FILE>` | `-o` | — | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | — | Increase log verbosity |

## Address hint table

| Address range | Typical devices |
|---------------|----------------|
| 0x18–0x19 | LIS3DH/LIS2DH accelerometer |
| 0x1C–0x1D | MMA8452/FXOS8700 accelerometer |
| 0x1E–0x1F | HMC5883L/MAG3110 magnetometer |
| 0x20–0x27 | PCF8574/MCP23017 GPIO expander |
| 0x28–0x29 | BNO055 IMU |
| 0x38–0x3B | PCF8574A GPIO expander / AHT10 humidity |
| 0x3C–0x3D | SSD1306/SH1106 OLED display |
| 0x40–0x41 | INA219 power monitor |
| 0x44–0x45 | SHT30/SHT31/SHT35 humidity & temperature |
| 0x48–0x4F | ADS1115 ADC / LM75/TMP102 temperature |
| 0x50–0x57 | 24Cxx I2C EEPROM |
| 0x60–0x67 | PCA9685 PWM driver |
| 0x68–0x69 | MPU-6050/9250 IMU / DS3231/DS1307 RTC |
| 0x70–0x75 | TCA9548A/PCA9548 I2C mux |
| 0x76–0x77 | BMP280/BME280/BMP388 pressure sensor |

## Example

```sh
$ iottack i2c i2c-scan --channel A --clock-hz 400000

Plugin name:    i2c/i2c-scan
Execution time: 312 ms
Status:         pass

[INFO] 3 I2C device(s) found on channel A
  Scanned addresses 0x08–0x77 at 400000 Hz on FTDI 0403:6011 channel A.

[MEDIUM] I2C device at 0x3c
  Address 0x3c (decimal 60) responded with ACK.
  Likely: SSD1306/SH1106 OLED display
  Evidence: "addr=0x3c hint=\"SSD1306/SH1106 OLED display\""

[MEDIUM] I2C device at 0x68
  Address 0x68 (decimal 104) responded with ACK.
  Likely: MPU-6050/9250 IMU / DS3231/DS1307 RTC
  Evidence: "addr=0x68 hint=\"MPU-6050/9250 IMU / DS3231/DS1307 RTC\""

[MEDIUM] I2C device at 0x76
  Address 0x76 (decimal 118) responded with ACK.
  Likely: BMP280/BME280/BMP388 pressure sensor
  Evidence: "addr=0x76 hint=\"BMP280/BME280/BMP388 pressure sensor\""
```

## Troubleshooting

**No devices found despite wiring being correct**

- Confirm pull-up resistors (4.7 kΩ) are present on SCL and SDA.
- Try a lower clock frequency (`--clock-hz 100000`).
- Verify target power is on.

**FTDI device not found**

- Check `lsusb` shows the adapter (`0403:6011` or similar).
- Apply the [udev rule](../hardware/ftdi.md#linux-setup-udev) and reconnect.

**MPSSE initialisation failed**

- Channels C and D on the FT4232H do not support MPSSE. Use `--channel A` or `--channel B`.
