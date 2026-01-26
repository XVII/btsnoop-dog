#!/usr/bin/env python3
"""
BLE Advertisement - Raw payload
"""

import socket
import struct
import time
import os
import sys

# Check if running as root
if os.geteuid() != 0:
    print("Error: This script requires root privileges")
    sys.exit(1)

# Create HCI socket
sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
sock.bind((0,))  # hci0

# The packets from the lamp seem to be longer than what is allowed in adv data
# There are 6 extra bytes that wont fit in adv data length
max_adv_data_len = 31

payload = bytes([
    0x21, 0x48, 0x52, 0x52, 0x46,  # Magic bytes
    0x01, 0x02, 0x03, 0x04, 0x05,  # Dummy values for testing
    0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, #0x18, #0x19,
    #0x1A, #0x1B, #0x1C, #0x1D
])

# Set advertising parameters
params = struct.pack('<HH B B B 6s B B',
    0x0640, 0x0640,  # Interval min/max (1000ms)
    0x00,  # ADV_IND
    0x00, 0x00, b'\x00'*6, 0x07, 0x00)  # Public addr, all channels
sock.send(b'\x01\x06\x20\x0f' + params)
time.sleep(0.1)

# Set advertising data
flags = b'\x02\x01\x06'  # LE General Discoverable + BR/EDR Not Supported
ad_data = flags + payload
ad_data = ad_data[:max_adv_data_len]  # Trim to 31 bytes if longer
ad_data = ad_data + b'\x00' * (max_adv_data_len - len(ad_data))  # Pad to exactly 31 bytes if shorter

# HCI command: 0x20 = 32 bytes total (1 length byte + 31 data bytes)
sock.send(b'\x01\x08\x20\x20' + struct.pack('B', len(flags + payload)) + ad_data)
time.sleep(0.1)

# Enable advertising
sock.send(b'\x01\x0a\x20\x01\x01')

print("Advertising started")
print(f"Payload: {payload.hex()}")
print("Press Ctrl+C to stop...")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    # Disable advertising
    sock.send(b'\x01\x0a\x20\x01\x00')
    sock.close()
    print("\nStopped")
