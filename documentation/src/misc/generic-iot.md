# Generic IoT Test Target (ESPHome)

A [WEMOS LOLIN S2 Mini](https://www.wemos.cc/en/latest/s2/s2_mini.html) is used as a
target or dummy device to demonstrate how the `iottack` plugins behave against a real
piece of IoT hardware. Any other ESP32-S2 based board can be substituted.

The device runs [ESPHome](https://esphome.io/) as its firmware. ESPHome exposes a
well-known set of network services (mDNS, the native API, a web server and OTA
updates), which makes the board a convenient target for the network plugins.

## Firmware

ESPHome is compiled for the `esp32s2` platform and flashed onto the board. The
configuration below enables the services that the `iottack` network plugins target:

- `mdns`: announces the device on the local network (see
  [mdns-scan](../plugins/network/mdns-scan.md))
- `web_server`: serves an HTTP interface on port 80
- `api`: the native ESPHome API on port 6053
- `ota`: over-the-air updates via the ESPHome dashboard

## ESPHome configuration

```yaml
# Board: LOLIN S2 Mini (LOLIN/Wemos)
# Definition: definitions/boards/esp32-s2-mini/manifest.yaml

esphome:
  name: iottack-target-device
  friendly_name: iottack Target device (ESPHome)

esp32:
  variant: esp32s2
  flash_size: 4MB
  framework:
    type: esp-idf

logger:

api:
  encryption:
    key: "2EXXjaLyzz9n13NZcjuDALwwIli7wyK/mfvLKssxHoA="

ota:
  - platform: esphome

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password
  ap:
    ssid: iottack Target  Fallback Hotspot
    password: "12345678"

captive_portal:

async_tcp:

mdns:

web_server:

text_sensor:
  - platform: uptime
    name: Uptime Text Sensor
    id: text_sensor_uptime_1
  - platform: version
    name: Version Text Sensor
    id: text_sensor_version_1
  - platform: wifi_info
    ip_address:
      name: IP Address
      id: wifi_info_ip_address
      address_0:
        name: Address 0
```

## Testing with iottack

Once flashed and connected to the network, the device can be discovered and
enumerated:

```sh
# Discover the device via mDNS
iottack network mdns-scan
```
