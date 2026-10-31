# Introduction

IoTtack is an open-source, Rust-based security framework designed for auditing and testing
common IoT protocols, hardware implementations and smart infrastructures. The modular tool
simplifies security assessments by offering automated plugins that probe everything from
network layers to physical serial interfaces.

Key Features:

- Multi-Layer Testing: Broad plugin ecosystem covering physical hardware interfaces (UART),
  protocol brokers (AMQP), web endpoints (HTTP) and network discoveries (mDNS, TCP).
- Hardware Auditing: Capabilities to run automated UART baud rate scanning, serial
  interface fuzzing and interactive shell detection.
- Built in Rust: Offers high performance, low-level memory safety and easy portability
  across target testing platforms.
- Developer Friendly: Extensible architecture making it simple to write custom configurations
  and register new protocol test suites.

Over the last 15 we contributed to various Open source projects that are the major players in
that (non)-commercial sector for IoT and home automation.

- Home Assistant: Support for MQTT, serial devices, RESTful API services, GPS, mathematical helpers,
  etc. Also, integrations that interfaces with micro controllers and alike. The binary sensor was
  something that was done front to end.
- ESPhome: Display and sensor support
- CircuitPython: Support for multiple RP2040-based boards
- Expliot: Multiple plugins, documentation and frontend

The involvement around the [local Hackerspace Eastermundigen](https://www.eastermundigen.ch/)
and [Bastelgarage](https://www.bastelgarage.ch/) multiple DIY kit were designed to give people
access to the Internet of Things.

Often is a serial-to-USB convert not enough and an oscilloscope too much. There is a lot of
software and tools available that could help in between. To close the gap we started to work
on IoTtack. Currently we are in the process of rewriting/cleaning up/improving piece by piece
to make the former inhouse solution completely Open Source.
 
