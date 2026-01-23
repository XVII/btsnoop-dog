# btsnoop-dog

LXJK-BDLA Bluetooth Control Protocol

Looking to reverse engineer the control protocol for the LX/JK Balloon Dog Lamp.
Message me if you're interested/able to help out :)

## Device

Model No: `LX-JK-BDL-A`
FCC ID: `2ARD3-LXJKBDLA` (?)

## Bluetooth Pairing Sequence

1. Press the nose of each lamp five times quickly to enable Bluetooth®.
2. Quickly press the nose of one lamp twice to connect.
3. Both lamps are now synchronized.

To disconnect a lamp, press its nose five times.

## Initial Notes

- The pairing sequence seems to be more about grouping/linking so that lamps can be grouped together. Without having more lamps, can't really test this.
- The dog only emits bluetooth advertisments when something is changed on the lamp (i.e. brightness, mode), there have been no idle adverstiments observed to date.
- No packets are sent on low battery, low battery power-off, battery charge start/stop.

## Resources

- [Manual](https://www.lexon-design.com/media/documents/manuals/bdl-balloon-dog-lamp-user-guide-2025.pdf)
