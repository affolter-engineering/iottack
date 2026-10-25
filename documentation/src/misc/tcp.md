# TCP Test Target

The TCP test target is a Python script that simulates nine vulnerable IoT services
on separate ports. It runs entirely in software with no physical hardware required, so
every `iottack tcp` plugin can be exercised locally.

Source: [`test-targets/iottack-target-tcp/iottack-tcp.py`](../../../test-targets/iottack-target-tcp/iottack-tcp.py)

## Requirements

Python 3.13 or later. No third-party packages/modules are needed.

## Services

| Service | Default port | Simulated vulnerability | Expected finding |
|---------|-------------|------------------------|-----------------|
| SSH | 2222 | Version disclosure in banner | Info |
| FTP | 2121 | `vsftpd 2.3.4`, any password accepted | High |
| Telnet | 2323 | Login prompt with weak credentials | High |
| HTTP | 8080 | Admin panel with firmware version disclosure | Low |
| Redis | 6379 | No authentication required | High |
| MQTT | 1883 | No authentication required | High |
| Modbus/TCP | 5020 | PLC registers readable without auth | High |
| Shell | 4444 | Unauthenticated root shell | Critical |
| Fuzz | 7777 | Buffer overflow and format string bugs | High |

## Usage

Start all services on localhost:

```sh
python test-targets/iottack-target-tcp/iottack-tcp.py
```

Start only a subset:

```sh
python test-targets/iottack-target-tcp/iottack-tcp.py --services shell,telnet,fuzz
```

Expose on all interfaces (use with care):

```sh
python test-targets/iottack-target-tcp/iottack-tcp.py --host 0.0.0.0
```

Override individual ports:

```sh
python test-targets/iottack-target-tcp/iottack-tcp.py --shell-port 9999 --fuzz-port 9998
```

Enable debug logging:

```sh
python test-targets/iottack-target-tcp/iottack-tcp.py -v
```

## Testing with iottack

### Banner grabbing

Scan all simulated services in one pass:

```sh
iottack tcp banner --host 127.0.0.1 \
    --ports 2222,2121,2323,8080,6379,1883,5020
```

### Shell detection

Unauthenticated root shell (Critical):

```sh
iottack tcp shell-detect --host 127.0.0.1 --port 4444
```

Telnet login prompt (High):

```sh
iottack tcp shell-detect --host 127.0.0.1 --port 2323
```

### Fuzzing

```sh
iottack tcp fuzz --host 127.0.0.1 --port 7777
```

With reconnect per payload to catch crash behaviour:

```sh
iottack tcp fuzz --host 127.0.0.1 --port 7777 --reconnect
```

## Telnet credentials

The Telnet service accepts any of these username/password combinations:

| Username | Password |
|----------|----------|
| `admin` | `admin` |
| `admin` | `root` |
| `root` | `root` |
| `root` | `password` |
| `guest` | `1234` |

Any other combination returns `Login incorrect`.

## Code

```python
{{#include ../../../test-targets/iottack-target-tcp/iottack-tcp.py}}
```
