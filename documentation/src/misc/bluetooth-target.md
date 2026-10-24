# Bluetooth Test Target

Some example in the Plugin documentation are showing how an actual approach
could be taken to exploit a device.

The hardware base for this test target device can be an ESP32 like ESP32-C3. The requirement
is that the ESP32 supports Bluetooth obviously. This means that an ESP32-Sx doesn't work.

Here a [ESP32-C6-LCD-1.47](https://docs.waveshare.com/ESP32-C6-LCD-1.47) is used. The
display shows which payload was received.

For simplicity, [ciruitpython](https://circuitpython.org/) act as the base firmware.
For further details about the usage or how to get started with circuitpython, check
their [documentation](https://learn.adafruit.com/welcome-to-circuitpython).

## Code

```python
import board
import time
import neopixel
import displayio
import terminalio
from adafruit_display_text import label
from adafruit_display_shapes.roundrect import RoundRect

# Core BLE classes
from adafruit_ble import BLERadio
from adafruit_ble.advertising.standard import ProvideServicesAdvertisement
from adafruit_ble.services import Service
from adafruit_ble.characteristics.string import StringCharacteristic
from adafruit_ble.uuid import VendorUUID

# 1. Custom BLE Service Architecture
class LEDControlService(Service):
    uuid = VendorUUID("19B10000-E8F2-537E-4F6C-D104768A1214")
    led_state = StringCharacteristic(
        uuid=VendorUUID("19B10001-E8F2-537E-4F6C-D104768A1214"),
        properties=StringCharacteristic.WRITE | StringCharacteristic.WRITE_NO_RESPONSE | StringCharacteristic.READ,
    )

# 2. Initialize Display and Rotate 90 Degrees
display = board.DISPLAY
display.rotation = 90  # Portrait mode layout boundary 
display.brightness = 0.5  # Reduces the heating up of the board

main_group = displayio.Group()

# Top Header: Device Name Display
DEVICE_NAME = "IoTTack Target Bluetooth"
name_label = label.Label(
    terminalio.FONT, text=DEVICE_NAME, color=0xAAAAAA, x=10, y=20, scale=2
)
main_group.append(name_label)

# Sub-Header: Active BLE Connection Output Label (Moved up to prevent off-screen clipping)
status_label = label.Label(
    terminalio.FONT, text="BLE: Init...", color=0xFFFFFF, x=10, y=45, scale=1
)
main_group.append(status_label)

# Middle Section: Max-Width Row of Color Status Boxes
box_w, box_h = 75, 80
box_y = 70  # Shifted down slightly to accommodate the sub-header text block
spacing = 8

# Box 1: Red Component Container
red_x = 5
red_box = RoundRect(red_x, box_y, box_w, box_h, 6, fill=0x220000, outline=0x550000, stroke=2)
red_label = label.Label(terminalio.FONT, text="red", color=0x555555, x=18, y=box_y + 60, scale=2)

# Box 2: Green Component Container
green_x = red_x + box_w + spacing
green_box = RoundRect(green_x, box_y, box_w, box_h, 6, fill=0x002200, outline=0x005500, stroke=2)
green_label = label.Label(terminalio.FONT, text="green", color=0x555555, x=green_x + 9, y=box_y + 60, scale=2)

# Box 3: Blue Component Container
blue_x = green_x + box_w + spacing
blue_box = RoundRect(blue_x, box_y, box_w, box_h, 6, fill=0x000022, outline=0x000055, stroke=2)
blue_label = label.Label(terminalio.FONT, text="blue", color=0x555555, x=blue_x + 12, y=box_y + 60, scale=2)

# Append structural objects to layer sequence
for item in (red_box, green_box, blue_box, red_label, green_label, blue_label):
    main_group.append(item)
display.root_group = main_group

# 3. Hardware Component Setup
pixel = neopixel.NeoPixel(board.NEOPIXEL, 1, brightness=0.3, auto_write=True)
pixel = (0, 0, 0)

# 4. Initialize Local Bluetooth Advertising Interface
ble = BLERadio()
ble.name = DEVICE_NAME
custom_service = LEDControlService()
advertisement = ProvideServicesAdvertisement(custom_service)

def update_ui_selection(active_color):
    """Updates display visual box fills based on string value."""
    red_box.fill, red_label.color = 0x220000, 0x555555
    green_box.fill, green_label.color = 0x002200, 0x555555
    blue_box.fill, blue_label.color = 0x000022, 0x555555
    
    if active_color == "R":
        red_box.fill, red_label.color = 0xFF0000, 0xFFFFFF
    elif active_color == "G":
        green_box.fill, green_label.color = 0x00FF00, 0x000000
    elif active_color == "B":
        blue_box.fill, blue_label.color = 0x0000FF, 0xFFFFFF

# Reset internal state tracking 
custom_service.led_state = ""
print("\n- System Initialization Complete ---")

# Main System Execution
while True:
    ble.start_advertising(advertisement)
    status_label.text = "BLE: Advertisement"
    status_label.color = 0xFFFF00
    print("[BLE State Change] Advertising for incoming connections...")
    
    while not ble.connected:
        pass
    
    ble.stop_advertising()
    status_label.text = "BLE: Connected"
    status_label.color = 0x00FF00
    print("[BLE State Change] Peer device successfully connected.")
    
    while ble.connected:
        raw_value = custom_service.led_state
        current_command = raw_value.strip().upper()

        if current_command:
            print(f"[BLE Write] Raw: {repr(raw_value)}  Parsed: '{current_command}'")
            
            if current_command == "R":
                pixel = (255, 0, 0)
                update_ui_selection("R")
                print("[Action Executed] Onboard LED configured to RED.")
            elif current_command == "G":
                pixel = (0, 255, 0)
                update_ui_selection("G")
                print("[Action Executed] Onboard LED configured to GREEN.")
            elif current_command == "B":
                pixel = (0, 0, 255)
                update_ui_selection("B")
                print("[Action Executed] Onboard LED configured to BLUE.")
            elif current_command == "O":
                pixel = (0, 0, 0)
                update_ui_selection("OFF")
                print("[Action Executed] Onboard LED powered OFF.")
            else:
                print(f"[Warning] Discarded invalid parameter argument: '{current_command}'")
                
            # Clear register to listen for next command state change
            custom_service.led_state = ""
            
        time.sleep(0.05)
        
    print("[BLE State Change] Peer disconnected. Resetting hardware registers...")
    pixel = (0, 0, 0)
    update_ui_selection("OFF")
```
