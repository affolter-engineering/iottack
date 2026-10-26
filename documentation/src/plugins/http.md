# HTTP

HTTP (Hypertext Transfer Protocol) is the application-layer protocol that
underpins web-based management interfaces, REST APIs, and over-the-air (OTA)
firmware update endpoints. All common features of modern IoT devices. Even
devices with no user-visible web interface often embed a lightweight HTTP server
for configuration, health checks, or telemetry reporting.

## How HTTP works

HTTP is a request-response protocol. A client opens a TCP connection, sends a
request with a method, path, headers and optional body. Then the server replies
with a status code, headers, and a response body.

```text
GET /api/status HTTP/1.1
Host: 192.168.1.1
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json

{"firmware":"1.4.2","uptime":86400}
```

### Key HTTP methods in IoT assessments

| Method | Typical use | Security relevance |
|--------|------------|-------------------|
| `GET` | Read config, status, sensor data | Unauthenticated reads expose data |
| `POST` | Submit commands, trigger actions | Unauthenticated writes can modify device state |
| `PUT` | Update config or firmware | OTA endpoints are high-value targets |
| `DELETE` | Remove records or reset | Dangerous if unauthenticated |

### HTTP versions

| Version | Transport | Notes |
|---------|-----------|-------|
| HTTP/1.0 | Plain TCP | No persistent connections; common on embedded devices |
| HTTP/1.1 | Plain TCP | Keep-alive, chunked transfer; most embedded web servers |
| HTTPS (TLS) | TLS over TCP | Encrypted; self-signed certificates are common on IoT |
| HTTP/2 | TLS or plain TCP | Rare on constrained devices |

## Attack surface

- **Admin panels without authentication**: embedded web servers frequently
  expose configuration pages with no login or with default credentials that
  are printed on the device label.
- **Firmware version disclosure**: the HTTP `Server` header and HTML pages
  often reveal exact firmware versions, enabling targeted exploitation.
- **Missing security headers**: IoT web interfaces commonly omit
  `Strict-Transport-Security`, `X-Frame-Options`, `Content-Security-Policy`
  and `X-Content-Type-Options`, enabling XSS and clickjacking.
- **Unencrypted management**: HTTP (not HTTPS) is used for configuration pages,
  exposing credentials to network eavesdroppers.
- **Unauthenticated REST APIs**: `/api/` endpoints that return sensor readings,
  device state, or accept commands without any token or session check.
- **Server-Sent Events (SSE)**: some devices stream live telemetry over SSE
  endpoints without authentication, leaking real-time operational data.

## Plugins

| Plugin | Command | Summary |
|--------|---------|---------|
| [http banner](./http/http-banner.md) | `iottack http banner` | Grab the HTTP banner and check response headers |
| [http sse](./http/http-sse.md) | `iottack http sse` | Consume a Server-Sent Events stream from a device endpoint |

## Typical workflow

1. **Grab the banner**: identify the server software, check for missing
   security headers, and look for version strings in the response.

   ```sh
   iottack http banner --host 192.168.1.1 --port 80
   ```

2. **Check HTTPS**: verify whether TLS is available and if the certificate
   is valid.

   ```sh
   iottack http banner --host 192.168.1.1 --port 443
   ```

3. **Probe SSE endpoints**: check whether live telemetry streams require
   authentication.

   ```sh
   iottack http sse --host 192.168.1.1 --path /api/events
   ```
