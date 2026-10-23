# Seeed Studio XIAO RP2040 (CircuitPython)

Some example in the Plugin documentation are showing how an actual approach
could be taken to exploit a device.

The hardware base for this "simulator", target or dummy device is a
[Seeed Studio XIAO RP2040](https://www.seeedstudio.com/XIAO-RP2040-v1-0-p-5026.html).
Pretty much every other device based on the RP 2040 could be used.

For simplicity, [ciruitpython](https://circuitpython.org/) act as the base firmware.
For further details about the usage or how to get started with circuitpython, check
their [documentation](https://learn.adafruit.com/welcome-to-circuitpython).

## Code for UART fuzz examples

This code simulates a IoT bulb which can be controlled over a serial connection.
The code accepts a number of command to interact with the build-in LED.

Add this code to `code.py` and add `neopixel.mpy` to the `libs` folder. Then reboot
the device with `Ctrl-D`.

```python
import board
import digitalio
import neopixel
import supervisor
import sys
import time

# Turn ON the power to the onboard NeoPixel
pixel_power = digitalio.DigitalInOut(board.NEOPIXEL_POWER)
pixel_power.direction = digitalio.Direction.OUTPUT
pixel_power.value = True

# Initialize the NeoPixel (1 pixel built into the board, uses GRB color ordering
pixel = neopixel.NeoPixel(board.NEOPIXEL, 1, brightness=0.3, pixel_order=neopixel.GRB)

# Define some colors (Red, Green, Blue)
BLACK = (0, 0, 0)  # Off
BLUE = (0, 0, 255)
GREEN = (0, 255, 0)
RED = (255, 0, 0)
YELLOW = (255, 255, 0)
    
# Helper function to generate rainbow colors (0-255)
def color_wheel(pos):
    if pos < 0 or pos > 255:
        return (0, 0, 0)
    if pos < 85:
        return (255 - pos * 3, pos * 3, 0)
    if pos < 170:
        pos -= 85
        return (0, 255 - pos * 3, pos * 3)
    pos -= 170
    return (pos * 3, 0, 255 - pos * 3)

# Shell and animation variables
input_buffer = ""
rainbow_active = False
rainbow_wheel_pos = 0
last_rainbow_update = 0

# Print instructions and the initial shell prompt
print("XIAO Shell: Type 'red', 'green', 'blue' or 'off'. Ctrl+C to exit.")
sys.stdout.write("xiao> ")

while True:
    # 1. Process standard keyboard inputs
    if supervisor.runtime.serial_bytes_available:
        char = sys.stdin.read(1)
        
        # Handle Enter key
        if char in ('\r', '\n'):
            sys.stdout.write("\n")
            command = input_buffer.strip().lower()
            
            if command == "green":
                rainbow_active = False
                pixel[0] = GREEN
                sys.stdout.write("Hit - Green\n")
            elif command == "red":
                rainbow_active = False
                pixel[0] = RED
                sys.stdout.write("Hit - Red\n")
            elif command == "blue":
                rainbow_active = False
                pixel[0] = BLUE
                sys.stdout.write("Hit - Blue\n")
            elif command == "abc":
                rainbow_active = True
                sys.stdout.write("Hit - Rainbow started!\n")
            elif command == "x":
                rainbow_active = False
                pixel[0] = YELLOW
                sys.stdout.write("Hit - x\n")
            elif command == "off":
                rainbow_active = False
                pixel[0] = BLACK
                sys.stdout.write("Hit - Off\n")
            elif command == "":
                pass
            else:
                sys.stdout.write(f"Unknown command: '{command}'\n")
                
            input_buffer = ""
            sys.stdout.write("xiao> ")
            
        # Handle Backspace key
        elif char in ('\x08', '\x7f'):
            if len(input_buffer) > 0:
                input_buffer = input_buffer[:-1]
                sys.stdout.write("\x08 \x08")
                
        # Handle printable text characters
        else:
            input_buffer += char
            sys.stdout.write(char)

    # Update the rainbow animation incrementally (non-blocking)
    if rainbow_active:
        current_time = time.monotonic()
        # Update the color roughly every 0.02 seconds (20ms) for a smooth cycle
        if current_time - last_rainbow_update > 0.02:
            pixel[0] = color_wheel(rainbow_wheel_pos)
            rainbow_wheel_pos = (rainbow_wheel_pos + 1) % 256
            last_rainbow_update = current_time
```

Once the code is uploaded to the device:

```bash
XIAO Shell: Type 'red', 'green', 'blue' or 'off'. Ctrl+C to exit.
xiao> green
Hit - Green
xiao> off
Hit - Off
```
