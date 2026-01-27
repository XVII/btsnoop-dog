-- Wireshark BLE Advertisement Data Dissector for Lexon x Jeff Koons Balloon Dog Lamp Protocol
-- Dissects BLE advertisement data emitted by the device
-- Reverse engineered by analyzing captured packets with the help of AI

-- Create a new protocol
local proto        = Proto("btle_lxjkbdla", "BLE Lexon x Jeff Koons Balloon Dog Lamp Protocol")

-- Define protocol fields
local fields            = proto.fields

-- Unknown Fields
fields.unknown_bytes1  = ProtoField.bytes("btle_lxjkbdla.unknown_bytes1", "Unknown Bytes 1", base.COLON)
fields.unknown_bytes2  = ProtoField.bytes("btle_lxjkbdla.unknown_bytes2", "Unknown Bytes 2", base.COLON)
fields.unknown_bytes3  = ProtoField.bytes("btle_lxjkbdla.unknown_bytes3", "Unknown Bytes 3", base.COLON)

-- Guessed fields
fields.expected_length  = ProtoField.string("btle_lxjkbdla.expected_length", "Expected Length", base.NONE)
fields.lamp_group_id    = ProtoField.bytes("btle_lxjkbdla.lamp_group_id", "Lamp Group ID", base.COLON)
fields.sequence_id      = ProtoField.uint8("btle_lxjkbdla.sequence_id", "Sequence ID (0-255)", base.DEC)

fields.all_bytes       = ProtoField.bytes("btle_lxjkbdla.all_bytes", "All Bytes", base.COLON)
fields.all_bytes_index = ProtoField.bytes("btle_lxjkbdla.all_bytes_index", "Hex Index", base.COLON)

-- Guessed Light Fields
fields.power_state       = ProtoField.uint8("btle_lxjkbdla.power_state", "Power State", base.DEC,
    { [0] = "Off", [1] = "On" })
fields.mode             = ProtoField.uint8("btle_lxjkbdla.mode", "Mode", base.DEC,
    { [0] = "Solid Color", [1] = "Sunset", [2] = "Rainbow Flow", [3] = "Fill", [4] = "Knight Rider", [5] =
    "Rainbow Cycle", [6] = "Slow Flow", [7] = "Breathing Rainbow Cycle", [8] = "Chase Solid", [9] = "Strobe", [10] =
    "Segment" })
fields.mode_mirror      = ProtoField.uint8("btle_lxjkbdla.mode_mirror", "Mode Mirror", base.DEC,
    { [0] = "Solid Color", [1] = "Sunset", [2] = "Rainbow Flow", [3] = "Fill", [4] = "Knight Rider", [5] =
    "Rainbow Cycle", [6] = "Slow Flow", [7] = "Breathing Rainbow Cycle", [8] = "Chase Solid", [9] = "Strobe", [10] =
    "Segment" })

fields.brightness       = ProtoField.uint16("btle_lxjkbdla.brightness", "Brightness", base.DEC)
fields.effect_direction = ProtoField.bytes("btle_lxjkbdla.effect_direction", "Effect Direction", base.NONE)
fields.effect_breathing_color = ProtoField.uint8("btle_lxjkbdla.effect_breathing_color", "Breathing Color", base.DEC,
    { [0] = "Red", [1] = "Green", [2] = "Blue", [3] = "Yellow", [4] = "Purple", [5] = "Cyan", [6] = "Cool White", [7] = "Warm Yellow", [8] = "Pink"  })
fields.effect_fill_color = ProtoField.uint8("btle_lxjkbdla.effect_fill_color", "Fill Color", base.DEC,
    { [0] = "0", [1] = "1", [2] = "2", [3] = "3", [4] = "4", [5] = "5", [6] = "6", [7] = "7", [8] = "8"  })
fields.effect_color     = ProtoField.uint8("btle_lxjkbdla.effect_color", "Effect Color", base.DEC, 
    { [0] = "Cool White", [1] = "Warm White", [2] = "Blue", [3] = "Orange", [4] = "Purple", [5] = "Pink", [6] = "Red", [7] = "Yellow", [8] = "Green" })

-- Define the magic number and offsets (all offsets relative to MAGIC_OFFSET)
local MAGIC_NUMBER     = { 0x21, 0x48, 0x52, 0x52, 0x46 }
local MAGIC_LENGTH     = #MAGIC_NUMBER
local MAGIC_OFFSET     = 32 -- absolute offset in packet // TODO: This may vary based on where the adv data is located and what flags are set, should probably be detected dynamically

local EXPECTED_LENGTH = 64 - MAGIC_OFFSET + 3 -- 3 extra bytes for BTLE CRC

-- Offsets relative to MAGIC_OFFSET
local LAMP_GROUP_ID_OFFSET = MAGIC_LENGTH                       -- immediately after magic
local LAMP_GROUP_ID_LENGTH = 6
local UNKNOWN1_OFFSET = MAGIC_LENGTH + 6
local UNKNOWN1_LENGTH = 2
local SEQUENCE_ID_OFFSET = MAGIC_LENGTH + 8
local SEQUENCE_ID_LENGTH = 1
local POWER_STATE_OFFSET = MAGIC_LENGTH + 9
local POWER_STATE_LENGTH = 1
local MODE_OFFSET = MAGIC_LENGTH + 10
local MODE_LENGTH = 1
local UNKNOWN2_OFFSET = MAGIC_LENGTH + 11
local UNKNOWN2_LENGTH = 4
local BRIGHTNESS_OFFSET = MAGIC_LENGTH + 15
local BRIGHTNESS_LENGTH = 2
local UNKNOWN3_OFFSET = MAGIC_LENGTH + 17
local UNKNOWN3_LENGTH = 5
local MODE_MIRROR_OFFSET = MAGIC_LENGTH + 22
local MODE_MIRROR_LENGTH = 1
local EFFECT_DIRECTION_OFFSET = MAGIC_LENGTH + 23
local EFFECT_DIRECTION_LENGTH = 1
local EFFECT_BREATHING_COLOR_OFFSET = MAGIC_LENGTH + 24
local EFFECT_BREATHING_COLOR_LENGTH = 1
local EFFECT_FILL_COLOR_OFFSET = MAGIC_LENGTH + 25
local EFFECT_FILL_COLOR_LENGTH = 1
local EFFECT_COLOR_OFFSET = MAGIC_LENGTH + 26                   -- This is a sub-mode for more than just colour -- need to map them out
local EFFECT_COLOR_LENGTH = 1

local function get_field_offset(relative_offset)
    return MAGIC_OFFSET + relative_offset
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
function proto.dissector(buffer, pinfo, tree)
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
    local subtree = tree:add(proto, buffer(), "Lexon x Jeff Koons Balloon Dog Lamp Data")

    -- Lamp Group ID (6 bytes after magic)
    local lamp_group_abs = get_field_offset(LAMP_GROUP_ID_OFFSET)
    if buffer:len() >= lamp_group_abs + LAMP_GROUP_ID_LENGTH then
        subtree:add(fields.lamp_group_id, buffer(lamp_group_abs, LAMP_GROUP_ID_LENGTH))
    end

    -- Unknown bytes (2 bytes after lamp group ID)
    local unknown1_abs = get_field_offset(UNKNOWN1_OFFSET)
    if buffer:len() >= unknown1_abs + UNKNOWN1_LENGTH then
        subtree:add(fields.unknown_bytes1, buffer(unknown1_abs, UNKNOWN1_LENGTH))
    end

    -- Sequence ID (after lamp group ID + 2 unknown bytes)
    local sequence_id_abs = get_field_offset(SEQUENCE_ID_OFFSET)
    if buffer:len() >= sequence_id_abs + SEQUENCE_ID_LENGTH then
        subtree:add(fields.sequence_id, buffer(sequence_id_abs, SEQUENCE_ID_LENGTH))
    end

    -- Power state parsing
    local power_state_abs = get_field_offset(POWER_STATE_OFFSET)
    if buffer:len() >= power_state_abs + POWER_STATE_LENGTH then
        subtree:add(fields.power_state, buffer(power_state_abs, POWER_STATE_LENGTH))
    end

    -- Mode parsing and info column formatting
    local mode_id_abs = get_field_offset(MODE_OFFSET)
    if buffer:len() >= mode_id_abs + MODE_LENGTH then
        subtree:add(fields.mode, buffer(mode_id_abs, MODE_LENGTH))
    end

    -- Unknown bytes (4 bytes after mode)
    local unknown2_abs = get_field_offset(UNKNOWN2_OFFSET)
    if buffer:len() >= unknown2_abs + UNKNOWN2_LENGTH then
        subtree:add(fields.unknown_bytes2, buffer(unknown2_abs, UNKNOWN2_LENGTH))
    end

    -- Brightness parsing
    local brightness_abs = get_field_offset(BRIGHTNESS_OFFSET)
    if buffer:len() >= brightness_abs + BRIGHTNESS_LENGTH then
        subtree:add(fields.brightness, buffer(brightness_abs, BRIGHTNESS_LENGTH))
    end

    -- Unknown bytes
    local unknown3_abs = get_field_offset(UNKNOWN3_OFFSET)
    if buffer:len() >= unknown3_abs + UNKNOWN3_LENGTH then
        subtree:add(fields.unknown_bytes3, buffer(unknown3_abs, UNKNOWN3_LENGTH))
    end

    -- Mode mirror parsing
    local mode_mirror_abs = get_field_offset(MODE_MIRROR_OFFSET)
    if buffer:len() >= mode_mirror_abs + MODE_MIRROR_LENGTH then
        subtree:add(fields.mode_mirror, buffer(mode_mirror_abs, MODE_MIRROR_LENGTH))
    end

    -- Effect direction
    local effect_direction_abs = get_field_offset(EFFECT_DIRECTION_OFFSET)
    if buffer:len() >= effect_direction_abs + EFFECT_DIRECTION_LENGTH then
        subtree:add(fields.effect_direction, buffer(effect_direction_abs, EFFECT_DIRECTION_LENGTH))
    end

    -- Effect breathing color
    local effect_breathing_color_abs = get_field_offset(EFFECT_BREATHING_COLOR_OFFSET)
    if buffer:len() >= effect_breathing_color_abs + EFFECT_BREATHING_COLOR_LENGTH then
        subtree:add(fields.effect_breathing_color, buffer(effect_breathing_color_abs, EFFECT_BREATHING_COLOR_LENGTH))
    end

    -- Effect fill color
    local effect_fill_color_abs = get_field_offset(EFFECT_FILL_COLOR_OFFSET)
    if buffer:len() >= effect_fill_color_abs + EFFECT_FILL_COLOR_LENGTH then
        subtree:add(fields.effect_fill_color, buffer(effect_fill_color_abs, EFFECT_FILL_COLOR_LENGTH))
    end

    -- Effect color
    local effect_color_abs = get_field_offset(EFFECT_COLOR_OFFSET)
    if buffer:len() >= effect_color_abs + EFFECT_COLOR_LENGTH then
        subtree:add(fields.effect_color, buffer(effect_color_abs, EFFECT_COLOR_LENGTH))
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
            local idx_tvb = idx_ba:tvb("Ref_IndexBytes")
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
register_postdissector(proto)
