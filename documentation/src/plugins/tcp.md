# TCP

TCP (Transmission Control Protocol) is the transport layer backbone of most
IoT network communication. Unlike UDP, TCP provides ordered, reliable,
connection-oriented delivery which makes it the protocol of choice for
industrial control systems, remote management interfaces, telemetry pipelines
and proprietary device APIs.

## How TCP works

A TCP connection is established with a three-way handshake:

```txt
Client  ->  SYN       ->  Server
Client  <-  SYN-ACK   <-  Server
Client  ->  ACK       ->  Server
          (connection open)
```

Once open, both sides can exchange data streams freely until either party
sends a FIN (orderly close) or RST (abrupt reset). Each octet in the stream
carries a sequence number and the receiver acknowledges receipt which
guaranteeing that data arrives complete and in order.

## Ports and IoT services

IoT devices commonly expose TCP services on well-known and vendor-specific ports:

| Port | Protocol | Risk if exposed |
|------|----------|----------------|
| 22 | SSH | Low (if hardened); High if default credentials |
| 23 | Telnet | High - cleartext credentials and session data |
| 80 / 8080 | HTTP | Medium - admin panel, firmware info disclosure |
| 443 / 8443 | HTTPS | Low (if TLS valid); Medium if self-signed |
| 502 | Modbus/TCP | High - unauthenticated PLC register access |
| 1883 | MQTT | High - unauthenticated message broker |
| 4840 | OPC-UA | Medium - depends on authentication mode |
| 6379 | Redis | High - no auth by default in older versions |
| 9100 | Raw print/JetDirect | Medium - direct print access |

## Attack surface

- **Banner disclosure**: many services announce their software name and version
  in the first bytes sent after connection. This enables targeted exploitation.
- **Cleartext protocols**: Telnet, plain HTTP, MQTT (port 1883) and Modbus/TCP
  transmit credentials and data without encryption.
- **Unauthenticated access**: industrial protocols (Modbus, DNP3, BACnet) were
  designed for isolated networks and have no built-in authentication.
- **Default credentials**: management interfaces (SSH, HTTP admin panels,
  Redis) often ship with well-known default credentials.
- **Fuzzing**: many embedded TCP stacks have limited input validation. Sending
  malformed or oversized payloads can reveal crashes or unexpected behavior.

## Plugins

| Plugin | Command | Summary |
|--------|---------|---------|
| [tcp banner](./tcp/banner.md) | `iottack tcp banner` | Connect and capture the service banner; identify protocol and flag cleartext services |
| [tcp shell-detect](./tcp/shell-detect.md) | `iottack tcp shell-detect` | Detect an interactive shell or login prompt on a TCP port |
| [tcp fuzz](./tcp/fuzz.md) | `iottack tcp fuzz` | Send malformed payloads and report anomalous responses |

## Typical workflow

1. **Banner grab**: identify what is listening on each open port.

   ```sh
   iottack tcp banner --host 192.168.1.1 --ports 22,23,80,502,1883,8080
   ```

2. **Shell detection**: check whether a port exposes an unauthenticated shell
   or a login prompt accepting default credentials.

   ```sh
   iottack tcp shell-detect --host 192.168.1.1 --port 23
   ```

3. **Fuzz**: send malformed inputs to look for crashes or unexpected behavior.

   ```sh
   iottack tcp fuzz --host 192.168.1.1 --port 8080
   ```
