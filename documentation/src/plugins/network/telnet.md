# network telnet

Connects to a Telnet service, captures the banner, strips IAC option-negotiation
bytes, and checks for login prompts, shell prompts, and default credentials.
Telnet is flagged as High severity unconditionally because it transmits
credentials and session data in cleartext.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | Connection succeeded (findings may include Critical/High issues) |
| `fail` | Telnet port not reachable |

## Severity classification

| Severity | Condition |
|----------|-----------|
| Critical | Unauthenticated shell prompt directly accessible **or** default credentials accepted |
| High | Telnet service is open (cleartext protocol) |
| Medium | Login prompt detected in banner or after stimulus |
| Info | Banner received, or no login prompt found |

## Usage

```sh
iottack network telnet --host <HOST> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required)* | Target IP address or hostname |
| `--port <PORT>` | `-p` | `23` | Target port |
| `--timeout-ms <MS>` | - | `3000` | Connection and read timeout in milliseconds |
| `--try-creds` | - | off | Probe common default credentials after finding a login prompt |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Detection logic

1. Connect to the target port with the configured timeout.
2. Read up to 2048 bytes and strip IAC option-negotiation sequences,
   replying DONT/WONT to any WILL/DO commands.
3. Scan the cleaned banner for login and shell prompt patterns.
4. If no prompt is found in the initial banner, send `\r\n` and check
   the response again.
5. If `--try-creds` is set and a login prompt was found, iterate the
   built-in credential list and check each response for a shell prompt.

### Login prompt patterns

`login:`, `Login:`, `username:`, `Username:`, `Password:`, `password:`,
`root@`, `admin@`, `BusyBox`, `busybox`, `U-Boot`, `bash`, `sh-`

### Shell prompt patterns (line-start)

`# `, `$ `, `root@`

### Default credentials tested (with `--try-creds`)

| Username | Password |
|----------|----------|
| `admin` | `admin` |
| `admin` | *(empty)* |
| `root` | `root` |
| `root` | *(empty)* |
| `admin` | `password` |
| `admin` | `1234` |
| `user` | `user` |
| `guest` | `guest` |

## Examples

Basic banner grab:

```sh
iottack network telnet --host 192.168.1.1
```

Non-standard port with extended timeout:

```sh
iottack network telnet --host 192.168.1.1 --port 2323 --timeout-ms 5000
```

Banner grab and default credential check:

```sh
iottack network telnet --host 192.168.1.1 --try-creds
```

Save result as JSON:

```sh
iottack network telnet --host 192.168.1.1 --try-creds \
  --format json --output telnet-result.json
```

## Example output

No authentication required — shell directly accessible:

```text
Plugin name:    network/telnet
Execution time: 0.31 s
Status:         pass

[HIGH] Telnet service open on 192.168.1.1:23
  Telnet transmits credentials and data in cleartext.
  Replace with SSH wherever possible.

[INFO] Telnet banner
  Banner received from 192.168.1.1:23.
  Evidence: "OpenWrt login:"

[CRITICAL] Unauthenticated shell on Telnet
  A root/shell prompt is directly accessible on 192.168.1.1:23 with no login required.
```

Login prompt found and default credentials accepted:

```text
Plugin name:    network/telnet
Execution time: 2.14 s
Status:         pass

[HIGH] Telnet service open on 192.168.1.1:23
  Telnet transmits credentials and data in cleartext.
  Replace with SSH wherever possible.

[INFO] Telnet banner
  Banner received from 192.168.1.1:23.
  Evidence: "BusyBox v1.36.1 (2024-01-15) built-in shell (ash)\nlogin:"

[MEDIUM] Login prompt detected
  A login prompt is accessible on 192.168.1.1:23. Test default credentials.

[CRITICAL] Default credentials accepted: admin/admin
  Telnet on 192.168.1.1:23 accepted admin/admin and returned a shell prompt.
  Evidence: "Password: \r\n# "
```
