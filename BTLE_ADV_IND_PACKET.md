# Advertising Data Payload: Field Summary

## Fields and Offsets

| Field Name | Relative Offset* | Absolute Offset** | Length | Description |
|------------|------------------|-------------------|--------|-------------|
| Magic Number | 0 | 32 | 5 bytes | `21 48 52 52 46` |
| Lamp Group ID | 5 | 37 | 6 bytes | Device group identifier (represents 1 or more lamps) |
| Unknown | 11 | 43 | 2 bytes | Purpose not yet identified |
| Sequence ID | 13 | 45 | 1 byte | Counter (0-255). Used to prevent issues with out of order BLE packets? |
| Mode | 15 | 47 | 1 byte | Lighting mode (0-10). See table below. |
| Brightness | 20 | 52 | 2 bytes | Brightness level (0-1000) |
| Effect Direction | 28 | 60 | 1 byte | Direction for effects? |
| Unknown | 29-30 | 61-62 | 2 bytes | Purpose not yet identified |
| Sunset Mode | 31 | 63 | 1 byte | 0=Cool, 1=Warm |

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

## Sunset Mode Values

| Value | Description |
|-------|-------------|
| 0 | Cool |
| 1 | Warm |
