#!/usr/bin/env python3
"""IoTtack TCP target is a multi-service test server for TCP attack scenarios.

Simulates twelve vulnerable IoT services on separate ports so that every
iottack TCP plugin (banner, shell-detect or fuzz) can be exercised locally
without real hardware.

Usage
-----
  python iottack-tcp.py                           # all services, 127.0.0.1
  python iottack-tcp.py --host 0.0.0.0            # expose on all interfaces
  python iottack-tcp.py --services ssh,ftp,redis  # start a subset
  python iottack-tcp.py --shell-port 9999 -v      # override a port

Services and expected plugin findings
--------------------------------------
  ssh    :2222 SSH-2.0 banner             -> banner Info
  ftp    :2121 vsftpd 2.3.4 (any pass)    -> banner High
  telnet :2323 IAC negotiation + login:   -> banner High / shell-detect High
  http   :8080 admin panel response       -> banner Low
  redis  :6379 no-auth Redis              -> banner High
  mqtt   :1883 MQTT broker (no auth)      -> banner High
  modbus :5020 Modbus/TCP PLC sim         -> banner High
  shell  :4444 unauthenticated root shell -> shell-detect Critical
  fuzz   :7777 buffer-overflow target     -> fuzz High
"""

import asyncio
import argparse
import logging
import struct
import sys
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("iottack-target")


async def handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle an incoming SSH connection."""
    log.info("SSH connect from %s", writer.get_extra_info("peername"))
    try:
        writer.write(b"SSH-2.0-OpenSSH_7.2p2 IoTtackOS-1.0\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(256), timeout=5.0)
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def handle_ftp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle an incoming FTP connection."""
    log.info("FTP connect from %s", writer.get_extra_info("peername"))
    try:
        writer.write(b"220 (vsftpd 2.3.4)\r\n")
        await writer.drain()
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if not line:
                break
            cmd = line.strip().upper()
            if cmd.startswith(b"USER"):
                writer.write(b"331 Please specify the password.\r\n")
            elif cmd.startswith(b"PASS"):
                writer.write(b"230 Login successful.\r\n")  # accept any password
            elif cmd.startswith(b"SYST"):
                writer.write(b"215 UNIX Type: L8\r\n")
            elif cmd.startswith(b"FEAT"):
                writer.write(b"211-Features:\r\n EPRT\r\n EPSV\r\n211 End\r\n")
            elif cmd.startswith(b"PWD"):
                writer.write(b'257 "/" is current directory.\r\n')
            elif cmd.startswith(b"LIST") or cmd.startswith(b"NLST"):
                writer.write(b"150 Here comes the directory listing.\r\n226 Directory send OK.\r\n")
            elif cmd.startswith(b"QUIT"):
                writer.write(b"221 Goodbye.\r\n")
                break
            else:
                writer.write(b"500 Unknown command.\r\n")
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


def _strip_iac(data: bytes) -> bytes:
    """Remove Telnet IAC command sequences from raw client data."""
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xFF and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(data):
                i += 3  # WILL/WONT/DO/DONT & option byte
            elif cmd == 0xFF:
                result.append(0xFF)
                i += 2
            else:
                i += 2
        else:
            result.append(data[i])
            i += 1
    return bytes(result)


async def handle_telnet(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle an incoming Telnet connection."""
    log.info("Telnet connect from %s", writer.get_extra_info("peername"))
    try:
        # IAC DO SUPPRESS-GO-AHEAD + IAC WILL ECHO, then banner and login prompt
        writer.write(b"\xff\xfd\x03\xff\xfb\x01\r\nIoTtack Test Device v1.0\r\n\r\nlogin: ")
        await writer.drain()

        username = _strip_iac(await asyncio.wait_for(reader.read(64), timeout=15.0)).strip().lower()
        writer.write(b"\r\nPassword: ")
        await writer.drain()
        password = _strip_iac(await asyncio.wait_for(reader.read(64), timeout=15.0)).strip().lower()

        weak_users = (b"admin", b"root", b"user", b"guest")
        weak_passes = (b"admin", b"root", b"password", b"1234", b"12345", b"")
        if username in weak_users and password in weak_passes:
            writer.write(b"\r\n# ")
            await writer.drain()
            while True:
                cmd = (await asyncio.wait_for(reader.readline(), timeout=60.0)).strip()
                if not cmd or cmd in (b"exit", b"logout"):
                    break
                if cmd == b"id":
                    reply = b"uid=0(root) gid=0(root) groups=0(root)\r\n# "
                elif cmd == b"whoami":
                    reply = b"root\r\n# "
                elif cmd == b"uname -a":
                    reply = b"Linux iottack-device 4.14.0 #1 SMP PREEMPT armv7l GNU/Linux\r\n# "
                elif cmd == b"cat /etc/passwd":
                    reply = b"root:x:0:0:root:/root:/bin/sh\r\nadmin:x:1000:1000::/home/admin:/bin/sh\r\n# "
                elif cmd.startswith(b"ls"):
                    reply = b"bin  dev  etc  lib  proc  root  sys  tmp  usr  var\r\n# "
                elif cmd == b"":
                    reply = b"# "
                else:
                    reply = cmd + b": not found\r\n# "
                writer.write(reply)
                await writer.drain()
        else:
            writer.write(b"\r\nLogin incorrect\r\n\r\nlogin: ")
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle an incoming HTTP connection."""
    log.info("HTTP   connect from %s", writer.get_extra_info("peername"))
    try:
        await asyncio.wait_for(reader.read(4096), timeout=10.0)
        body = (
            b"<html><head><title>IoTtack Device Admin</title></head>"
            b"<body><h1>IoTtack Device Admin Panel</h1>"
            b"<p>Firmware: 1.0.0 | Model: IoTtack-T1</p>"
            b"</body></html>"
        )
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: IoT-HTTPD/1.0\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def handle_redis(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle an incoming Redis connection."""
    log.info("Redis connect from %s", writer.get_extra_info("peername"))
    try:
        while True:
            data = await asyncio.wait_for(reader.read(256), timeout=10.0)
            if not data:
                break
            upper = data.decode(errors="replace").upper()
            if "PING" in upper:
                writer.write(b"+PONG\r\n")
            elif "INFO" in upper:
                info = (
                    b"# Server\r\nredis_version:2.8.17\r\nredis_mode:standalone\r\n"
                    b"os:Linux 4.14.0 armv7l\r\nconfig_file:/etc/redis/redis.conf\r\n"
                )
                writer.write(b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n")
            elif "CONFIG" in upper:
                writer.write(b"*2\r\n$4\r\nbind\r\n$9\r\n0.0.0.0\r\n")
            elif "QUIT" in upper:
                writer.write(b"+OK\r\n")
                break
            else:
                writer.write(b"-ERR unknown command\r\n")
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def handle_mqtt(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle an incoming MQTT connection."""
    log.info("MQTT connect from %s", writer.get_extra_info("peername"))
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=10.0)
        if not data or data[0] != 0x10:  # CONNECT packet type
            return
        # CONNACK: accepted, no session present
        writer.write(b"\x20\x02\x00\x00")
        await writer.drain()
        while True:
            pkt = await asyncio.wait_for(reader.read(256), timeout=30.0)
            if not pkt:
                break
            pkt_type = (pkt[0] & 0xF0) >> 4
            if pkt_type == 14:    # DISCONNECT
                break
            elif pkt_type == 12:  # PINGREQ -> PINGRESP
                writer.write(b"\xd0\x00")
                await writer.drain()
            elif pkt_type == 8 and len(pkt) >= 4:  # SUBSCRIBE -> SUBACK
                writer.write(b"\x90\x03" + pkt[2:4] + b"\x00")
                await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def handle_modbus(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle an incoming Modbus connection."""
    log.info("Modbus connect from %s", writer.get_extra_info("peername"))
    try:
        while True:
            header = await asyncio.wait_for(reader.readexactly(6), timeout=10.0)
            trans_id = header[0:2]
            length = struct.unpack(">H", header[4:6])[0]
            pdu = await asyncio.wait_for(reader.readexactly(length), timeout=5.0)
            if not pdu:
                break
            unit_id = pdu[0]
            func_code = pdu[1] if len(pdu) > 1 else 0x00

            if func_code == 0x03:  # Read Holding Registers
                reg_data = b"\x00\x01\x00\x02"
                body = bytes([unit_id, func_code, len(reg_data)]) + reg_data
            elif func_code == 0x01:  # Read Coils
                body = bytes([unit_id, func_code, 1, 0x01])
            elif func_code == 0x2B:  # Read Device Identification
                vendor = b"IoT Corp"
                body = bytes([unit_id, func_code, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01, len(vendor)]) + vendor
            else:
                body = bytes([unit_id, func_code | 0x80, 0x01])  # illegal function exception

            writer.write(trans_id + b"\x00\x00" + struct.pack(">H", len(body)) + body)
            await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def handle_shell(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Unauthenticated root shell. No credentials required (Critical finding)."""
    log.info("Shell connect from %s (unauthenticated)", writer.get_extra_info("peername"))
    try:
        writer.write(b"root@iottack:~# ")
        await writer.drain()
        while True:
            cmd = (await asyncio.wait_for(reader.readline(), timeout=60.0)).strip()
            if not cmd or cmd in (b"exit", b"logout"):
                break
            if cmd == b"id":
                reply = b"uid=0(root) gid=0(root) groups=0(root)\r\nroot@iottack:~# "
            elif cmd == b"whoami":
                reply = b"root\r\nroot@iottack:~# "
            elif cmd == b"uname -a":
                reply = b"Linux iottack 4.14.0 #1 SMP PREEMPT armv7l GNU/Linux\r\nroot@iottack:~# "
            elif cmd == b"cat /etc/passwd":
                reply = b"root:x:0:0:root:/root:/bin/sh\r\nadmin::1000:1000::/home/admin:/bin/sh\r\nroot@iottack:~# "
            elif cmd == b"cat /etc/shadow":
                reply = b"root:$1$IoTtarget$abc123:0:0:99999:7:::\r\nadmin::0:0:99999:7:::\r\nroot@iottack:~# "
            elif cmd.startswith(b"ls"):
                reply = b"bin  dev  etc  lib  proc  root  sys  tmp  usr  var\r\nroot@iottack:~# "
            elif cmd == b"":
                reply = b"root@iottack:~# "
            else:
                reply = cmd + b": command not found\r\nroot@iottack:~# "
            writer.write(reply)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def handle_fuzz(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Fuzz target: simulates buffer overflow, format-string and path-traversal bugs."""
    log.info("Fuzz connect from %s", writer.get_extra_info("peername"))
    try:
        writer.write(b"READY\r\n")
        await writer.drain()
        while True:
            data = await asyncio.wait_for(reader.read(4096), timeout=10.0)
            if not data:
                break
            if len(data) > 512:
                writer.write(b"ERROR: input too long -- buffer overflow\r\n")
                break
            if b"\x00" in data:
                writer.write(b"ERROR: null byte in input\r\n")
                break
            if b"%s" in data or b"%n" in data or b"%x" in data:
                writer.write(b"ERROR: format string in input\r\n")
            elif b"/../" in data or b"../" in data:
                writer.write(b"ERROR: path traversal attempt\r\n")
            elif data.strip().upper() in (b"ADMIN", b"ROOT"):
                writer.write(b"ACCESS GRANTED\r\n")
            else:
                writer.write(b"OK: " + data[:256])
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


@dataclass
class ServiceDef:
    name: str
    handler: Callable
    default_port: int
    description: str


SERVICES: list[ServiceDef] = [
    ServiceDef("ssh", handle_ssh, 2222, "SSH-2.0 banner (Info)"),
    ServiceDef("ftp", handle_ftp, 2121, "vsftpd 2.3.4, any password accepted (High)"),
    ServiceDef("telnet", handle_telnet, 2323, "Telnet login prompt, weak creds succeed (High)"),
    ServiceDef("http", handle_http, 8080, "HTTP admin panel with info disclosure (Low)"),
    ServiceDef("redis", handle_redis, 6379, "Redis with no authentication (High)"),
    ServiceDef("mqtt", handle_mqtt, 1883, "MQTT broker with no authentication (High)"),
    ServiceDef("modbus", handle_modbus, 5020, "Modbus/TCP PLC simulation (High)"),
    ServiceDef("shell", handle_shell, 4444, "Unauthenticated root shell (Critical)"),
    ServiceDef("fuzz", handle_fuzz, 7777, "Buffer-overflow/format-string target (High)"),
]


async def _amain(args: argparse.Namespace) -> None:
    """Main entry point for the TCP service target."""
    if args.services == "all":
        enabled = {s.name for s in SERVICES}
    else:
        enabled = {x.strip().lower() for x in args.services.split(",")}

    servers = []
    for svc in SERVICES:
        if svc.name not in enabled:
            continue
        port: int = getattr(args, f"{svc.name}_port")
        try:
            srv = await asyncio.start_server(svc.handler, args.host, port)
            servers.append((svc.name, port, srv))
            log.info("%-8s  %s:%d - %s", svc.name.upper(), args.host, port, svc.description)
        except OSError as exc:
            log.error("%-8s  cannot bind on %s:%d - %s", svc.name, args.host, port, exc)

    if not servers:
        log.error("No services started, exiting")
        sys.exit(1)

    log.info("%d service(s) running. Ctrl-C to stop.", len(servers))
    tasks = [asyncio.create_task(srv.serve_forever()) for _, _, srv in servers]
    try:
        await asyncio.gather(*tasks)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        for _, _, srv in servers:
            srv.close()
            await srv.wait_closed()
        log.info("All services stopped.")


def main() -> None:
    """IoTtack TCP test target."""
    svc_names = ", ".join(s.name for s in SERVICES)
    parser = argparse.ArgumentParser(
        description="IoTtack TCP test target to simulate vulnerable IoT services.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Default ports:\n"
            + "\n".join(f"  {s.name:<8} :{s.default_port:<5}  {s.description}" for s in SERVICES)
            + "\n\nExamples:\n"
            "  python iottack-tcp.py\n"
            "  python iottack-tcp.py --host 0.0.0.0 -v\n"
            "  python iottack-tcp.py --services shell,fuzz,telnet\n"
            "  python iottack-tcp.py --shell-port 9999 --fuzz-port 9998\n"
            "\n"
            "Test with iottack banner plugin:\n"
            f"  iottack tcp banner --host 127.0.0.1 --ports 2222,2121,2323,2525,1100,1430,5900,8080,6379,1883,5020\n"
            "\n"
            "Test shell-detect:\n"
            "  iottack tcp shell-detect --host 127.0.0.1 --port 4444   # Critical\n"
            "  iottack tcp shell-detect --host 127.0.0.1 --port 2323   # High\n"
            "\n"
            "Test fuzz:\n"
            "  iottack tcp fuzz --host 127.0.0.1 --port 7777\n"
        ),
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Bind address (default: 127.0.0.1, use 0.0.0.0 to expose on all interfaces)",
    )
    parser.add_argument(
        "--services", default="all", metavar="LIST",
        help=f"Comma-separated services to start or 'all'. Available: {svc_names}",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    for svc in SERVICES:
        parser.add_argument(
            f"--{svc.name}-port", type=int, default=svc.default_port,
            metavar="PORT", dest=f"{svc.name}_port",
            help=f"{svc.name} port (default: {svc.default_port})",
        )

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
    )
    try:
        asyncio.run(_amain(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
