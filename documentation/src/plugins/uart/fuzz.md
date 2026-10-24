# uart fuzz

Sends a sequence of payloads through a serial port and inspects each response
for patterns that indicate crashes, errors, shell exposure, or any user-defined
string. The built-in payload set covers common vulnerability classes (null
bytes, long strings, format strings, shell metacharacters, boundary values,
control characters). When `--charset` or `--wordlist` is supplied the built-in
set is replaced so only the specified payloads are sent. Named payload sets
(`--payload-set`) always add to whatever is already configured.

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
iottack uart fuzz --port <PATH> [OPTIONS]
```
### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port <PATH>` | `-p` | *(required)* | Serial port device, e.g. `/dev/ttyUSB0` |
| `--baud-rate <BAUD>` | `-b` | `115200` | Baud rate |
| `--timeout-ms <MS>` | - | `500` | Read timeout per payload in milliseconds |
| `--iterations <N>` | - | `1` | Times to repeat the full payload set |
| `--charset <CHARS>` | `-c` | - | Characters to fuzz — generates one payload per character per length step (replaces built-ins) |
| `--length <N>` | `-l` | `16` | Maximum repeat length for charset payloads |
| `--wordlist <PATH>` | `-w` | - | Wordlist file, one payload per line (replaces built-ins) |
| `--suffix <BYTES>` | `-s` | - | Bytes appended to every payload, e.g. `\r\n` for line-oriented shells |
| `--pattern <STRING>` | - | - | Extra response pattern to flag as interesting |
| `--delay-ms <MS>` | `-d` | `0` | Delay between payloads in milliseconds |
| `--payload-set <SETS>` | - | - | Named payload sets to add, comma-separated (`digits`, `lowercase`, `uppercase`, `ascii`) |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity (repeat for debug/trace) |

## Examples

### Built-in payload set

```sh
iottack uart fuzz --port /dev/ttyUSB0
```

### Charset fuzzing against a line-oriented shell

Generate every combination of the given characters up to length 8
(`a`, `b`, ..., `aa`, `ab`, ..., `zz`, `aaa`, ...), append `\r\n` so
the shell processes each entry, and flag any response containing
`Set command`.
Total payloads = |charset|¹ + |charset|² + ... + |charset|^length — keep
`--length` small for large charsets.

```sh
iottack uart fuzz --port /dev/ttyUSB0 \
  --charset "abcdefghijklmnopqrstuvwxyz0123456789" \
  --length 8 \
  --suffix '\r\n' \
  --pattern 'Set command '
```

### Wordlist fuzzing

```sh
iottack uart fuzz --port /dev/ttyUSB0 \
  --wordlist /path/to/commands.txt \
  --suffix '\r\n' \
  --delay-ms 100
```

### Named payload sets

Four built-in named sets are available. Unlike `--charset` and `--wordlist`,
named sets always **add** to the active payload list — they never replace the
built-in set (or a wordlist/charset if one is also specified).

| Set name | Contents |
|----------|----------|
| `digits` | `1234567890` repeated to lengths 10, 64, 256 |
| `lowercase` | `a–z` repeated to lengths 26, 64, 256 |
| `uppercase` | `A–Z` repeated to lengths 26, 64, 256 |
| `ascii` | All 95 printable ASCII characters (0x20–0x7E), lengths 95, 128, 256 |

Add the digits set on top of the built-in payloads:

```sh
iottack uart fuzz --port /dev/ttyUSB0 \
  --payload-set digits \
  --suffix '\r\n'
```

Combine several sets at once using a comma-separated list:

```sh
iottack uart fuzz --port /dev/ttyUSB0 \
  --payload-set digits,lowercase,uppercase,ascii \
  --suffix '\r\n' \
  --delay-ms 50
```

Use named sets alongside a wordlist (the wordlist replaces the built-ins, the
named sets are appended on top):

```sh
iottack uart fuzz --port /dev/ttyUSB0 \
  --wordlist commands.txt \
  --payload-set digits,ascii \
  --suffix '\r\n'
```

## Wordlist format

Plain text, one payload per line. Blank lines and lines starting with `#` are
skipped. The line is sent as-is (without a trailing newline unless `--suffix`
adds one).

```text
# commands.txt
help
version
debug
admin
reboot
```

## Demo

The [XIAO RP2040](../../misc/xiao-rp2040.md) target runs a CircuitPython shell
that controls an onboard NeoPixel LED. The shell accepts a handful of commands
(`red`, `green`, `blue`, `off`, `abc`, `x`) and echoes `Hit - <command>` for
each recognized one. Unknown commands produce `Unknown command: '...'`.

The commands are not documented. The goal is to discover them via fuzzing.

### Step 1: Discover single-character commands

`--charset` now generates every combination of the given characters up to the
specified length: `a`, `b`, ..., `aa`, `ab`, ..., `aaa`, `aab`, `abc`, etc.

Start with `--length 1` to find single-character commands quickly:

```sh
iottack uart fuzz --port /dev/ttyACM0 \
  --charset "abcdefghijklmnopqrstuvwxyz0123456789" \
  --length 1 \
  --suffix '\r\n' \
  --pattern 'Hit -' \
  --delay-ms 250
```

`x` triggers a `Hit -` response, so the plugin reports `pass`:

```sh
Plugin name:    uart/fuzz
Execution time: 9.25 s
Status:         pass
Date:           2026-10-17 12:15:34 UTC

Interesting response to 'x' payload
  /dev/ttyACM0 responded with patterns [Hit -] after receiving the 'x' payload.
  Evidence: "x\nHit - x\nxiao> "
```

### Step 2: Discover multi-character commands

Extend to `--length 3` to reach commands like `abc` (3 chars) and `off`
(3 chars). For a 26-letter charset this generates
26 + 676 + 17 576 = 18 278 payloads — use a generous `--delay-ms` to avoid
overwhelming the device:

```sh
iottack uart fuzz --port /dev/ttyACM0 \
  --charset "abcdefghijklmnopqrstuvwxyz" \
  --length 3 \
  --suffix '\r\n' \
  --pattern 'Hit -' \
  --delay-ms 50
```

`abc`, `off`, `red` and all other 1-3-letter commands are found. Commands
longer than 3 characters (`blue`, `green`) require increasing `--length` to 5,
or use a wordlist for targeted enumeration.

### Step 3: Targeted wordlist

Once candidate commands are known, switch to a wordlist for exact matches:

```sh
iottack uart fuzz --port /dev/ttyACM0 \
  --wordlist commands.txt \
  --suffix '\r\n' \
  --pattern 'Hit -' \
  --delay-ms 100
```

`commands.txt`:

```text
red
green
blue
abc
rainbow
off
reboot
factory-reset
```

Only `red`, `green`, `blue`, `off`, and `abc` produce `Hit -` responses;
the others return `Unknown command:`.
