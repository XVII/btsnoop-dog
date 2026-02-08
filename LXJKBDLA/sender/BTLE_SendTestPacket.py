#!/usr/bin/env python3
"""
BLE Legacy Advertisement - Raw payload using BlueZ D-Bus API
"""

import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
import sys

# D-Bus service and interface names
BLUEZ_SERVICE_NAME = 'org.bluez'
LE_ADVERTISING_MANAGER_IFACE = 'org.bluez.LEAdvertisingManager1'
DBUS_OM_IFACE = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROP_IFACE = 'org.freedesktop.DBus.Properties'
LE_ADVERTISEMENT_IFACE = 'org.bluez.LEAdvertisement1'

COMPANY_ID = dbus.UInt16(0x2100)
PAYLOAD = bytes([
        0x48, 0x52, 0x52, 0x46, # Magic bytes (passing the first byte as company ID)
        0x00, 0x00, 0x00, 0x00, 0x00, # Group ID
        0x00, 0x00, # Unknown
        0x00, # Sequence ID
        0x00, # Power State
        0x00, # Mode
        0x00, 0x00, 0x00, 0x00, # Unknown
        0x00, 0x00, # Brightness
        0x00, 0x00, 0x00, 0x00, 0x00, # Unknown
        0x00, # Mode (Copy))
        0x01, # Effect Direction
        ## The following can't currently fit in payload
        # 0x00, # Effect Breathing Color
        # 0x00, # Effect Fill Color
        # 0x00, # Effect Color
    ])

# Simple Advertisement class - required by BlueZ D-Bus
class Advertisement(dbus.service.Object):
    
    def __init__(self, bus, path, ad_type, company_id=COMPANY_ID, payload_data=PAYLOAD):
        self.path = path
        self.bus = bus
        self.ad_type = ad_type
        self.company_id = company_id
        self.manufacturer_data = payload_data
        dbus.service.Object.__init__(self, bus, self.path)

    @dbus.service.method(DBUS_PROP_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, interface):
        if interface != LE_ADVERTISEMENT_IFACE:
            raise dbus.exceptions.DBusException(
                'org.freedesktop.DBus.Error.InvalidArgs',
                'Invalid interface')
        
        # Legacy advertising with flags and ManufacturerData
        # Flags: 0x06 = General Discoverable (0x02) + BR/EDR Not Supported (0x04)
        properties = {
            'Type': self.ad_type,
            # 'Discoverable': dbus.Boolean(True),  # Adds flags 0x02 0x01 0x06 to packet
            'ManufacturerData': dbus.Dictionary({
                self.company_id: self.manufacturer_data
            }, signature='qv'),
        }
        return properties

    @dbus.service.method(LE_ADVERTISEMENT_IFACE, in_signature='', out_signature='')
    def Release(self):
        print(f'{self.path}: Released!')

    def get_path(self):
        return dbus.ObjectPath(self.path)


def main():
    print("BLE Legacy Advertisement - Starting...")
    
    # Step 1: Initialize D-Bus
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    print("✓ D-Bus initialized")
    
    # Step 2: Find Bluetooth adapter
    print("\nSearching for Bluetooth adapter...")
    remote_om = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, '/'), DBUS_OM_IFACE)
    objects = remote_om.GetManagedObjects()
    
    adapter_path = None
    for path, interfaces in objects.items():
        if LE_ADVERTISING_MANAGER_IFACE in interfaces:
            adapter_path = path
            break
    
    if not adapter_path:
        print('✗ Error: No Bluetooth adapter found')
        sys.exit(1)
    
    print(f'✓ Found adapter: {adapter_path}')
    
    # Step 3: Get adapter properties and turn it on
    adapter_props = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE_NAME, adapter_path),
        DBUS_PROP_IFACE
    )
    
    adapter_address = adapter_props.Get('org.bluez.Adapter1', 'Address')
    print(f'✓ Adapter address: {adapter_address}')
    
    print("\nPowering on adapter...")
    adapter_props.Set('org.bluez.Adapter1', 'Powered', dbus.Boolean(1))
    print("✓ Adapter powered on")
    
    # Step 4: Prepare the raw payload for legacy advertising
    print("\nPreparing legacy advertisement payload...")
    
    print(f"✓ Company ID: 0x{COMPANY_ID:04x}")
    print(f"✓ Payload ({len(PAYLOAD)} bytes): {PAYLOAD.hex()}")
    
    # Convert payload to D-Bus array format
    payload_dbus = dbus.Array([dbus.Byte(b) for b in PAYLOAD], signature='y')
    
    # Step 5: Create legacy advertisement object
    advertisement_path = '/org/bluez/advertisement0'
    # Use 'peripheral' type for connectable legacy advertising (ADV_IND)
    advertisement = Advertisement(bus, advertisement_path, 'peripheral', COMPANY_ID, payload_dbus)
    
    # Step 6: Get advertising manager interface
    ad_manager = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE_NAME, adapter_path),
        LE_ADVERTISING_MANAGER_IFACE
    )
    
    # Step 7: Register the advertisement
    print("\nRegistering advertisement...")
    
    registration_complete = False
    
    def on_register_success():
        nonlocal registration_complete
        registration_complete = True
        print('✓ Advertisement registered successfully')
        print('Press Ctrl+C to stop...\n')
    
    def on_register_error(error):
        print(f'✗ Failed to register advertisement: {error}')
        mainloop.quit()
    
    ad_manager.RegisterAdvertisement(
        advertisement.get_path(),
        {},
        reply_handler=on_register_success,
        error_handler=on_register_error
    )
    
    # Step 8: Start main event loop
    mainloop = GLib.MainLoop()
    
    try:
        mainloop.run()
    except KeyboardInterrupt:
        print('\n\nStopping advertisement...')
    finally:
        # Step 9: Clean up - unregister advertisement
        if registration_complete:
            ad_manager.UnregisterAdvertisement(advertisement.get_path())
            print('✓ Advertisement unregistered')
        print('Done.')


if __name__ == '__main__':
    main()
