# tcp fuzz

Connects to a TCP host and port, sends a sequence of payloads, and inspects
each response for patterns that indicate crashes, errors, shell exposure, or
any user-defined string. The built-in payload set covers common vulnerability
classes (null bytes, long strings, format strings, shell metacharacters,
boundary values, control characters). When `--charset` or `--wordlist` is
supplied the built-in set is replaced so only the specified payloads are sent.
Named payload sets (`--payload-set`) always add to whatever is already
configured.

Use `--reconnect` to open a fresh TCP connection for every payload. Useful
when the service closes the connection after each message, or when you want to
avoid session state between payloads.

## Status

| Result | Meaning |
|--------|---------|
| `pass` | At least one payload produced an interesting response (Medium severity) |
| `fail` | A High/Critical pattern matched (crash, shell prompt) **or** no response matched at all |

## Severity classification

| Severity | Matched patterns |
|----------|-----------------|
| Critical | `fault`, `panic`, `exception`, `stack`, `crash`, `abort`, `segfault`, `overflow` |
| High | `root@`, `# `, `$ `, `login:`, `password:` |
| Medium | Everything else (`error`, `invalid`, user `--pattern` strings) |

## Usage

```sh
iottack tcp fuzz --host <HOST> --port <PORT> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required)* | Target hostname or IP address |
| `--port <PORT>` | `-p` | *(required)* | Target TCP port |
| `--timeout-ms <MS>` | - | `3000` | Connect and read timeout in milliseconds |
| `--reconnect` | `-r` | off | Open a new TCP connection for every payload |
| `--iterations <N>` | - | `1` | Times to repeat the full payload set |
| `--charset <CHARS>` | `-c` | - | Characters to fuzz. Generates one payload per character per length step (replaces built-ins) |
| `--length <N>` | `-l` | `16` | Maximum repeat length for charset payloads |
| `--wordlist <PATH>` | `-w` | - | Wordlist file, one payload per line (replaces built-ins) |
| `--suffix <BYTES>` | `-s` | - | Bytes appended to every payload, e.g., `\r\n` for line-oriented services |
| `--pattern <STRING>` | - | - | Extra response pattern to flag as interesting |
| `--delay-ms <MS>` | `-d` | `0` | Delay between payloads in milliseconds |
| `--payload-set <SETS>` | - | - | Named payload sets to add, comma-separated (`digits`, `lowercase`, `uppercase`, `ascii`) |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | - | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity (repeat for debug/trace) |

## Examples

### Built-in payload set

```sh
iottack tcp fuzz --host 192.168.1.1 --port 4444
```

### Reconnect mode for stateless services

Some services (HTTP/1.0, custom embedded daemons) close the connection after
each exchange. Use `--reconnect` to open a fresh connection per payload:

```sh
iottack tcp fuzz --host 192.168.1.1 --port 9999 --reconnect
```

### Charset fuzzing against a line-oriented service

Generate every combination of the given characters up to the specified length
and append `\r\n` so the service processes each entry as a line:

```sh
iottack tcp fuzz --host 192.168.1.1 --port 4444 \
  --charset "abcdefghijklmnopqrstuvwxyz" \
  --length 4 \
  --suffix '\r\n' \
  --pattern 'OK'
```

### Wordlist fuzzing

```sh
iottack tcp fuzz --host 192.168.1.1 --port 4444 \
  --wordlist /path/to/commands.txt \
  --suffix '\r\n' \
  --delay-ms 100
```

### Named payload sets

Four built-in named sets are available. Each set sends one payload per
character (single byte). When specified, built-in payloads are replaced
unless a wordlist or charset is also given.

| Set name | Contents |
|----------|----------|
| `digits` | `0–9`, one payload per digit |
| `lowercase` | `a–z`, one payload per letter |
| `uppercase` | `A–Z`, one payload per letter |
| `ascii` | All 95 printable ASCII characters (0x20-0x7E), one per character |

Send each uppercase letter individually as a single-byte payload:

```sh
iottack tcp fuzz --host 192.168.1.1 --port 4444 \
  --payload-set uppercase \
  --delay-ms 200
```

Combine several sets:

```sh
iottack tcp fuzz --host 192.168.1.1 --port 4444 \
  --payload-set digits,lowercase,uppercase \
  --suffix '\r\n'
```

### Save result as JSON

```sh
iottack tcp fuzz --host 192.168.1.1 --port 4444 \
  --format json --output tcp-fuzz.json
```

## Wordlist format

Plain text, one payload per line. Blank lines and lines starting with `#` are
skipped. The line is sent as-is (without a trailing newline unless `--suffix`
adds one).

```text
# commands.txt
help
version
admin
reboot
```

## Example output

```text
Plugin name:    tcp/fuzz
Execution time: 3.41 s
Status:         fail

[HIGH] Interesting response to null-byte payload
  192.168.1.1:4444 responded with patterns [login:] after receiving the null-byte payload.
  Evidence: "login: "

[MEDIUM] Interesting response to 'AAAA...' payload
  192.168.1.1:4444 responded with patterns [error] after receiving the 'AAAA...' payload.
  Evidence: "error: invalid input"
```
