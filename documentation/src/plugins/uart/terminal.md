# uart terminal

Connects to the serial port and bridges your terminal to the device: everything
you type is forwarded byte-for-byte to the device, and everything the device
sends is printed to stdout.

Press **Ctrl+D** (EOF) to end the session. The plugin also exits cleanly if the
device is reset or unplugged mid-session.

No findings are reported — this plugin is an interactive utility, not an
automated check.

## Usage

```sh
iottack uart terminal --port <PATH> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port <PATH>` | `-p` | *(required)* | Serial port device, e.g. `/dev/ttyUSB0` |
| `--baud-rate <BAUD>` | `-b` | `115200` | Baud rate |
| `--timeout-ms <MS>` | - | `50` | Read timeout in milliseconds |

## Example

```sh
$ iottack uart terminal --port /dev/ttyUSB0 --baud-rate 115200
[iottack] connected to /dev/ttyUSB0 at 115200 baud - Ctrl+D to exit

OpenWrt login: root
Password:
BusyBox v1.36.1 (2024-01-12) built-in shell (ash)

root@OpenWrt:~# uname -a
Linux OpenWrt 6.1.74 #0 SMP ...

root@OpenWrt:~#
[iottack] session ended
```

## Tips

- Run `uart baud-scan` first if you do not know the baud rate.
- Run `uart shell-detect` to confirm a shell is present before opening a terminal.
- If the device echoes your input back, check whether the firmware has local echo enabled; most IoT shells do not.
- For devices that require `\r\n` line endings, prefix your commands accordingly or configure your terminal emulator before launching this plugin.
