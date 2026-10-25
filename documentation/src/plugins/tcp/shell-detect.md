# tcp shell-detect

Connects to a TCP host and port, reads the initial banner, then sends a
configurable stimulus (default: `\r\n`) up to `--attempts` times and checks
all received output for shell and login prompt patterns.

Unauthenticated root shells are reported as Critical. Login prompts are
reported as High with a suggestion to test default credentials. Other
interactive prompts (e.g., `$`, `>`) are reported as Medium. Boot messages
are reported as Info and do not affect the status.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | Connection succeeded (findings may include Critical/High/Medium issues) |
| `fail` | No response received after banner read and all stimulus attempts |

## Severity classification

| Severity | Condition |
|----------|-----------|
| Critical | `# ` or `root@` present — unauthenticated root shell directly accessible |
| High | `login:`, `Login:`, `Password:`, `password:` present. Login prompt exposed |
| Medium | Other shell indicators matched (`$ `, `> `, `bash`, `sh-`, etc.) |
| Info | Boot messages detected, or service responded but no prompt found |

## Usage

```sh
iottack tcp shell-detect --host <HOST> --port <PORT> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required)* | Target hostname or IP address |
| `--port <PORT>` | `-p` | *(required)* | Target TCP port |
| `--timeout-ms <MS>` | - | `3000` | Connect and read timeout in milliseconds |
| `--attempts <N>` | - | `3` | Number of stimulus attempts after the initial banner |
| `--stimulus <BYTES>` | `-S` | `\r\n` | Bytes to send as stimulus, e.g. `\r\n` or `help\r\n` |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Detection logic

1. Connect to the target host and port with the configured timeout.
2. Read the initial banner (up to 8 KiB).
3. Send the configured stimulus up to `--attempts` times, collecting all responses.
4. Search the combined output for shell and login prompt patterns.
5. Classify the highest severity match found.

### Shell patterns

`# `, `$ `, `> `, `bash`, `sh-`, `ash`, `busybox`, `root@`, `admin@`,
`BusyBox`, `U-Boot`, `Press ENTER`, `press enter`, `Hit any key`

### Login prompt patterns

`login:`, `Login:`, `Password:`, `password:`

### Boot message patterns (Info only)

`Booting`, `booting`, `Starting`, `Loading`, `Kernel`, `U-Boot`, `GRUB`,
`init:`, `systemd`

## Examples

Basic shell detection on a custom TCP port:

```sh
iottack tcp shell-detect --host 192.168.1.1 --port 4444
```

Non-default port with extended timeout and more attempts:

```sh
iottack tcp shell-detect --host 192.168.1.1 --port 2323 \
  --timeout-ms 5000 --attempts 5
```

Send a custom stimulus to wake the service:

```sh
iottack tcp shell-detect --host 192.168.1.1 --port 9999 \
  --stimulus 'help\r\n'
```

Save result as JSON:

```sh
iottack tcp shell-detect --host 192.168.1.1 --port 4444 \
  --format json --output shell-detect.json
```

## Example output

Unauthenticated root shell directly accessible:

```text
Plugin name:    tcp/shell-detect
Execution time: 0.24 s
Status:         pass

[CRITICAL] Unauthenticated root shell on 192.168.1.1:4444
  A root shell is directly accessible on 192.168.1.1:4444 with no authentication required.
  Evidence: "root@device:~# "
```

Login prompt exposed:

```text
Plugin name:    tcp/shell-detect
Execution time: 0.31 s
Status:         pass

[HIGH] Login prompt exposed on 192.168.1.1:2323
  A login prompt is accessible on 192.168.1.1:2323.
  Test default credentials with 'iottack network telnet --try-creds'.
  Evidence: "OpenWrt login: "
```

Device still booting:

```text
Plugin name:    tcp/shell-detect
Execution time: 3.01 s
Status:         fail

[INFO] Boot messages detected
  Device appears to be booting (matched: Starting, systemd).
  Evidence: "Starting kernel ...\n[  0.000000] Linux version 5.15"
```
