-- Wireshark BLE Advertisement Data Dissector for Lexon x Jeff Koons Balloon Dog Protocol
-- Dissects BLE advertisement data emitted by the Balloon Dog device
-- Reverse engineered by analyzing captured packets with the help of AI

-- Create a new protocol
local ble_lxjkbd        = Proto("ble_lxjkbd", "BLE Lexon x Jeff Koons Balloon Dog Lamp Protocol")

-- Define protocol fields
local fields            = ble_lxjkbd.fields

-- Guessed fields
fields.expected_length  = ProtoField.string("ble_lxjkbd.expected_length", "Expected Length", base.NONE)
fields.lamp_group_id    = ProtoField.bytes("ble_lxjkbd.lamp_group_id", "Lamp Group ID", base.COLON)
fields.sequence_id      = ProtoField.uint8("ble_lxjkbd.sequence_id", "Sequence ID (0-255)", base.DEC)
fields.mode             = ProtoField.uint8("ble_lxjkbd.mode", "Mode", base.DEC,
    { [0] = "Solid Color", [1] = "Sunset", [2] = "Rainbow Flow", [3] = "Fill", [4] = "Knight Rider", [5] =
    "Rainbow Cycle", [6] = "Slow Flow", [7] = "Breathing Rainbow Cycle", [8] = "Chase Solid", [9] = "Strobe", [10] =
    "Segment" })

fields.bright           = ProtoField.uint16("ble_lxjkbd.brightness", "Brightness", base.DEC)

fields.effect_direction = ProtoField.bytes("ble_lxjkbd.effect_direction", "Effect Direction", base.NONE)
fields.sunset_mode     = ProtoField.uint8("ble_lxjkbd.sunset_mode", "Sunset Mode", base.DEC, { [0] = "Cool", [1] = "Warm"})

fields.all_bytes       = ProtoField.bytes("ble_lxjkbd.all_bytes", "All Bytes", base.COLON)
fields.all_bytes_index = ProtoField.bytes("ble_lxjkbd.all_bytes_index", "Hex Index", base.COLON)

-- Define the magic number and offsets (all offsets relative to MAGIC_OFFSET)
local MAGIC_NUMBER     = { 0x21, 0x48, 0x52, 0x52, 0x46 }
local MAGIC_LENGTH     = #MAGIC_NUMBER
local MAGIC_OFFSET     = 32 -- absolute offset in packet


-- Offsets relative to MAGIC_OFFSET
local LAMP_GROUP_ID_OFFSET = MAGIC_LENGTH                          -- immediately after magic
local LAMP_GROUP_ID_LENGTH = 6
local SEQUENCE_ID_OFFSET = MAGIC_LENGTH + LAMP_GROUP_ID_LENGTH + 2 -- 2 unknown bytes after lamp group
local SEQUENCE_ID_LENGTH = 1
local LAMP_MODE_OFFSET = MAGIC_LENGTH + 10                         -- Also seems to be at byte +22 and +23?
local LAMP_MODE_LENGTH = 1
local BRIGHTNESS_OFFSET = MAGIC_LENGTH + 15
local BRIGHTNESS_LENGTH = 2
local EFFECT_DIRECTION_OFFSET = MAGIC_LENGTH + 23
local EFFECT_DIRECTION_LENGTH = 1
local SUNSET_MODE_OFFSET = MAGIC_LENGTH + 26
local SUNSET_MODE_LENGTH = 1
local EXPECTED_LENGTH = 64 - MAGIC_OFFSET  -- Excludes 3-byte BT CRC at end

local function get_field_offset(relative_offset)
    return MAGIC_OFFSET + relative_offset
end

local function range_to_hex(range)
    local bytes = range:bytes()
    return bytes:tohex(false, "")
end

-- Function to check if bytes match magic number
local function check_magic_number(buffer, offset)
    if buffer:len() < offset + MAGIC_LENGTH then
        return false
    end

    for i = 0, MAGIC_LENGTH - 1 do
        if buffer(offset + i, 1):uint() ~= MAGIC_NUMBER[i + 1] then
            return false
        end
    end

    return true
end

-- Dissector function
function ble_lxjkbd.dissector(buffer, pinfo, tree)
    -- Check if buffer has sufficient length for magic number
    if buffer:len() < MAGIC_OFFSET + MAGIC_LENGTH then
        return 0
    end

    -- Check for magic number in advertisement data
    local has_magic = check_magic_number(buffer, MAGIC_OFFSET)

    if not has_magic then
        return 0
    end

    -- Set protocol in column
    pinfo.cols.protocol = "BLE Lexon x Jeff Koons Balloon Dog Lamp Protocol"

    -- Create main subtree
    local subtree = tree:add(ble_lxjkbd, buffer(), "Lexon x Jeff Koons Balloon Dog Lamp Data")

    -- Lamp Group ID (6 bytes after magic)
    local lamp_group_abs = get_field_offset(LAMP_GROUP_ID_OFFSET)
    if buffer:len() >= lamp_group_abs + LAMP_GROUP_ID_LENGTH then
        subtree:add(fields.lamp_group_id, buffer(lamp_group_abs, LAMP_GROUP_ID_LENGTH))
    end

    -- Sequence ID (after lamp group ID + 2 unknown bytes)
    local sequence_id_abs = get_field_offset(SEQUENCE_ID_OFFSET)
    if buffer:len() >= sequence_id_abs + SEQUENCE_ID_LENGTH then
        subtree:add(fields.sequence_id, buffer(sequence_id_abs, SEQUENCE_ID_LENGTH))
    end

    -- Mode parsing and info column formatting
    local mode_id_abs = get_field_offset(LAMP_MODE_OFFSET)
    if buffer:len() >= mode_id_abs + LAMP_MODE_LENGTH then
        subtree:add(fields.mode, buffer(mode_id_abs, LAMP_MODE_LENGTH))
    end

    -- Brightness parsing
    local brightness_abs = get_field_offset(BRIGHTNESS_OFFSET)
    if buffer:len() >= brightness_abs + BRIGHTNESS_LENGTH then
        subtree:add(fields.bright, buffer(brightness_abs, BRIGHTNESS_LENGTH))
    end

    -- Effect direction
    local effect_direction_abs = get_field_offset(EFFECT_DIRECTION_OFFSET)
    if buffer:len() >= effect_direction_abs + EFFECT_DIRECTION_LENGTH then
        subtree:add(fields.effect_direction, buffer(effect_direction_abs, EFFECT_DIRECTION_LENGTH))
    end

    -- Sunset mode
    local sunset_mode_abs = get_field_offset(SUNSET_MODE_OFFSET)
    if buffer:len() >= sunset_mode_abs + SUNSET_MODE_LENGTH then
        subtree:add(fields.sunset_mode, buffer(sunset_mode_abs, SUNSET_MODE_LENGTH))
    end

    -- All bytes post-magic (everything after magic number for debugging)
    local all_bytes_abs = get_field_offset(MAGIC_LENGTH)
    if buffer:len() > all_bytes_abs then
        local all_bytes = buffer(all_bytes_abs, buffer:len() - all_bytes_abs)
        subtree:add(fields.all_bytes, all_bytes)

        -- Add indexed bytes
        local idx_len = all_bytes:len()
        if idx_len > 0 then
            local idx_hex = {}
            for i = 0, idx_len - 1 do
                idx_hex[i + 1] = string.format("%02x", i)
            end
            local idx_ba = ByteArray.new(table.concat(idx_hex))
            local idx_tvb = idx_ba:tvb("IndexBytes")
            subtree:add(fields.all_bytes_index, idx_tvb(0, idx_len))
        end
    end

    -- Check for unexpected data length
    local expected_abs = get_field_offset(EXPECTED_LENGTH)
    if buffer:len() > expected_abs then
        subtree:add(fields.expected_length,
            "Longer: Buffer length (" ..
            buffer:len() ..
            " bytes) exceeds expected (" .. expected_abs .. " bytes) - possibly an undiscovered format variant")
    elseif buffer:len() == expected_abs then
        subtree:add(fields.expected_length, "Standard")
    elseif buffer:len() < expected_abs then
        subtree:add(fields.expected_length,
            "Shorter: Buffer length (" ..
            buffer:len() ..
            " bytes) less than expected (" .. expected_abs .. " bytes) - possibly an undiscovered format variant")
    end

    return buffer:len()
end

-- Register the dissector
register_postdissector(ble_lxjkbd)
