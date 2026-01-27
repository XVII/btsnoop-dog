# btsnoop-dog

LXJK-BDLA Bluetooth Control Protocol

Looking to reverse engineer the control protocol for the LX/JK Balloon Dog Lamp. Message me if you're interested/able to help out :)

## Target Device

Model No: `LX-JK-BDL-A`

FCC ID: `2ARD3-LXJKBDLA` (01/21/2026)

## Resources

- [Manual](https://www.lexon-design.com/media/documents/manuals/bdl-balloon-dog-lamp-user-guide-2025.pdf)

### Bluetooth Pairing Sequence

1. Press the nose of each lamp five times quickly to enable Bluetooth®.
2. Quickly press the nose of one lamp twice to connect.
3. Both lamps are now synchronized.

To disconnect a lamp, press its nose five times.

# Payload Analysis

## Initial Notes

- The pairing sequence seems to be more about grouping/linking so that lamps can be grouped together. Without having more lamps, can't really test this.
- The dog only emits bluetooth advertisments when something is changed on the lamp (i.e. brightness, mode), there have been no idle adverstiments observed to date.
- No packets are sent on low battery, low battery power-off, battery charge start/stop.

## Fields and Offsets

| Field Name | Relative Offset* | Absolute Offset** | Length | Description |
|------------|------------------|-------------------|--------|-------------|
| Magic Number | 0 | 32 | 5 bytes | `21 48 52 52 46` |
| Lamp Group ID | 5 | 37 | 6 bytes | Device group identifier (represents 1 or more lamps) |
| Unknown #1 | 11 | 43 | 2 bytes | Purpose not yet identified |
| Sequence ID | 13 | 45 | 1 byte | Counter (0-255). Used to prevent issues with out of order BLE packets? |
| Power State | 14 | 46 | 1 byte | 0=Off, 1=On |
| Mode | 15 | 47 | 1 byte | Lighting mode (0-10). See table below. |
| Unknown #2 | 16 | 48 | 4 bytes | Purpose not yet identified |
| Brightness | 20 | 52 | 2 bytes | Brightness level (0-1000) |
| Unknown #3 | 22 | 54 | 6 bytes | Purpose not yet identified |
| Effect Direction | 28 | 60 | 1 byte | Direction for effects? |
| Effect Breathing Color | 29 | 61 | 1 byte | Color for breathing effects. See table below. |
| Unknown #4 | 30 | 62 | 1 byte | Purpose not yet identified |
| Effect Color | 31 | 63 | 1 byte | Color settings. See table below. |

\* Relative to the magic number start (offset 0 = first byte of magic)  
\*\* Absolute offset in the BLE packet

## Sample Payload

32 bytes of lamp protocol data starting at 0x20 (32 dec)

| Offset | Value |
| ------ | ------------------------------------------------- |
| `0020` | `21 48 52 52 46 79 40 06 cc 92 59 a4 6b 1f 01 02` |
| `0030` | `00 f0 03 e8 02 e4 00 01 64 00 02 02 00 04 00 09` |

## Mode Values

| Value | Mode Name |
|-------|-----------|
| 0 | Solid Color |
| 1 | Sunset |
| 2 | Rainbow Flow |
| 3 | Fill |
| 4 | Knight Rider |
| 5 | Rainbow Cycle |
| 6 | Slow Flow |
| 7 | Breathing Rainbow Cycle |
| 8 | Chase Solid |
| 9 | Strobe |
| 10 | Segment |

## Effect Breathing Color Values

| Value | Description |
|-------|-------------|
| 0 | Red |
| 1 | Green |
| 2 | Blue |
| 3 | Yellow |
| 4 | Purple |
| 5 | Cyan |
| 6 | Cool White |
| 7 | Warm Yellow |
| 8 | Pink |

## Effect Color Values

| Value | Description |
|-------|-------------|
| 0 | Cool White |
| 1 | Warm White |
| 2 | Blue |
| 3 | Orange |
| 4 | Purple |
| 5 | Pink |
| 6 | Red |
| 7 | Yellow |
| 8 | Green |
