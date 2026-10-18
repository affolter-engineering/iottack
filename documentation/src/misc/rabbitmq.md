# AMQP server

To test and to get yourself familiar with AMQP, a local [RabbitMQ](https://www.rabbitmq.com/)
server is useful.

On NixOS you can spin-up a AMQP server by enabling it in the `configuration.nix`
file:

```text
  services.rabbitmq = {
    enable = true;
    managementPlugin.enable = true;
  };
```

For more options, check the [options](https://search.nixos.org/options?channel=unstable&query=services.rabbitmq&type=options).

After `sudo nixos-rebuild switch`, the server is available.

```bash
$ http http://localhost:15672
HTTP/1.1 200 OK
allow: HEAD, GET, OPTIONS
[...]
server: Cowboy
vary: origin, accept-encoding
```
