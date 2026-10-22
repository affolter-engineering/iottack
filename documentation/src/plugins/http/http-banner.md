# http banner

Sends a `GET` request to the target and inspects the response for security
issues, version disclosure, and missing hardening headers.

## Checks performed

| Check | Finding | Severity |
|-------|---------|----------|
| `Server:` header with version number | Version disclosure | Medium |
| `Server:` header without version | Software identity | Info |
| `X-Powered-By:` header present | Framework/runtime disclosure | Medium |
| Port 80 with no HTTPS redirect | Cleartext HTTP | High |
| Port 80 redirecting to HTTPS | HTTPS redirect in place | Info |
| Missing `Strict-Transport-Security` (port 443) | No HSTS | Medium |
| Missing `X-Frame-Options` / `CSP frame-ancestors` | No clickjacking protection | Low |
| Missing `X-Content-Type-Options` | MIME sniffing not disabled | Low |
| Missing `Content-Security-Policy` | No CSP | Low |
| HTTP 401 with `Basic` scheme | Credentials over cleartext | High |
| HTTP 401 with other scheme | Auth required | Info |
| Default installation page in body | Server not customised | Medium |
| Cookie missing `Secure` or `HttpOnly` flag | Insecure cookie | Medium |

## Usage

```sh
iottack http http-banner --host <HOST> [OPTIONS]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host <HOST>` | `-H` | *(required)* | Target hostname or IP address |
| `--port <PORT>` | `-p` | `80` | TCP port |
| `--path <PATH>` | `-u` | `/` | Request path |
| `--timeout-ms <MS>` | `-t` | `5000` | Connect and read timeout (ms) |
| `--output <FILE>` | `-o` | - | Save result to a file |
| `--format <FORMAT>` | `-f` | `text` | `text` or `json` |
| `--verbose` | `-v` | - | Increase log verbosity |

## Examples

Check a device web interface:

```sh
$ iottack http http-banner --host 192.168.1.1
[...]
HTTP 200 OK
  Target: 192.168.1.1:80/

Server header: Apache/2.4.51 (Debian)
  Server header discloses software version. Consider suppressing or generalizing this header.

Cleartext HTTP on port 80
  Service responds to plain HTTP without redirecting to HTTPS.

Missing X-Frame-Options / CSP frame-ancestors
  No clickjacking protection header found.

Missing X-Content-Type-Options

Missing Content-Security-Policy
```

Check a non-standard port:

```sh
$ iottack http http-banner --host 192.168.1.1 --port 8080 --path /admin
```

Check HTTPS (port 443) for HSTS and security headers:

```sh
$ iottack http http-banner --host 192.168.1.1 --port 443
```
