-- Wireshark BLE Advertisement Data Dissector for Lexon x Jeff Koons Balloon Dog Lamp Protocol
-- Dissects BLE advertisement data emitted by the device
-- Reverse engineered by analyzing captured packets with the help of AI

-- Create a new protocol
local proto        = Proto("btle_lxjkbdla", "BLE Lexon x Jeff Koons Balloon Dog Lamp Protocol")

-- Define protocol fields
local fields            = proto.fields

-- Unknown Fields
fields.unknown_bytes1  = ProtoField.bytes(proto.name .. ".unknown_bytes1", "Unknown Bytes 1", base.COLON)
fields.unknown_bytes2  = ProtoField.bytes(proto.name .. ".unknown_bytes2", "Unknown Bytes 2", base.COLON)
fields.unknown_bytes3  = ProtoField.bytes(proto.name .. ".unknown_bytes3", "Unknown Bytes 3", base.COLON)

-- Guessed fields
fields.expected_length  = ProtoField.string(proto.name .. ".expected_length", "Expected Length", base.NONE)
fields.lamp_group_id    = ProtoField.bytes(proto.name .. ".lamp_group_id", "Lamp Group ID", base.COLON)
fields.sequence_id      = ProtoField.uint8(proto.name .. ".sequence_id", "Sequence ID (0-255)", base.DEC)

fields.all_bytes       = ProtoField.bytes(proto.name .. ".all_bytes", "All Bytes", base.COLON)
fields.all_bytes_index = ProtoField.bytes(proto.name .. ".all_bytes_index", "Hex Index", base.COLON)

-- Guessed Light Fields
fields.power_state       = ProtoField.uint8(proto.name .. ".power_state", "Power State", base.DEC,
    { [0] = "Off", [1] = "On" })
fields.mode             = ProtoField.uint8(proto.name .. ".mode", "Mode", base.DEC,
    { [0] = "Solid Color", [1] = "Sunset", [2] = "Rainbow Flow", [3] = "Fill", [4] = "Knight Rider", [5] =
    "Rainbow Cycle", [6] = "Slow Flow", [7] = "Breathing Rainbow Cycle", [8] = "Chase Solid", [9] = "Strobe", [10] =
    "Segment" })
fields.mode_mirror      = ProtoField.uint8(proto.name .. ".mode_mirror", "Mode Mirror", base.DEC,
    { [0] = "Solid Color", [1] = "Sunset", [2] = "Rainbow Flow", [3] = "Fill", [4] = "Knight Rider", [5] =
    "Rainbow Cycle", [6] = "Slow Flow", [7] = "Breathing Rainbow Cycle", [8] = "Chase Solid", [9] = "Strobe", [10] =
    "Segment" })

fields.brightness       = ProtoField.uint16(proto.name .. ".brightness", "Brightness", base.DEC)
fields.effect_direction = ProtoField.bytes(proto.name .. ".effect_direction", "Effect Direction", base.NONE)
fields.effect_breathing_color = ProtoField.uint8(proto.name .. ".effect_breathing_color", "Breathing Color", base.DEC,
    { [0] = "Red", [1] = "Green", [2] = "Blue", [3] = "Yellow", [4] = "Purple", [5] = "Cyan", [6] = "Cool White", [7] = "Warm Yellow", [8] = "Pink"  })
fields.effect_fill_color = ProtoField.uint8(proto.name .. ".effect_fill_color", "Fill Color", base.DEC,
    { [0] = "0", [1] = "1", [2] = "2", [3] = "3", [4] = "4", [5] = "5", [6] = "6", [7] = "7", [8] = "8"  })
fields.effect_color     = ProtoField.uint8(proto.name .. ".effect_color", "Effect Color", base.DEC, 
    { [0] = "Cool White", [1] = "Warm White", [2] = "Blue", [3] = "Orange", [4] = "Purple", [5] = "Pink", [6] = "Red", [7] = "Yellow", [8] = "Green" })

-- Define the magic number and offsets
local EXPECTED_LENGTH  = 27 -- Payload after magic (32 total - 5 magic)
local BTLE_CRC_LENGTH  = 3  -- BTLE CRC at end of packet

local MAGIC_NUMBER     = { 0x21, 0x48, 0x52, 0x52, 0x46 }
local MAGIC_LENGTH     = #MAGIC_NUMBER

-- Field definitions: offset (relative to magic) and length
local FIELD_DEFS = {
    lamp_group_id = { offset = MAGIC_LENGTH, length = 6 },
    unknown1 = { offset = MAGIC_LENGTH + 6, length = 2 },
    sequence_id = { offset = MAGIC_LENGTH + 8, length = 1 },
    power_state = { offset = MAGIC_LENGTH + 9, length = 1 },
    mode = { offset = MAGIC_LENGTH + 10, length = 1 },
    unknown2 = { offset = MAGIC_LENGTH + 11, length = 4 },
    brightness = { offset = MAGIC_LENGTH + 15, length = 2 },
    unknown3 = { offset = MAGIC_LENGTH + 17, length = 5 },
    mode_mirror = { offset = MAGIC_LENGTH + 22, length = 1 },
    effect_direction = { offset = MAGIC_LENGTH + 23, length = 1 },
    effect_breathing_color = { offset = MAGIC_LENGTH + 24, length = 1 },
    effect_fill_color = { offset = MAGIC_LENGTH + 25, length = 1 },
    effect_color = { offset = MAGIC_LENGTH + 26, length = 1 }, -- This is a sub-mode for more than just colour
}


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

-- Function to find magic number offset in buffer
local function find_magic_offset(buffer)
    for offset = 0, buffer:len() - MAGIC_LENGTH do
        if check_magic_number(buffer, offset) then
            return offset
        end
    end
    return nil
end

-- Dissector function
function proto.dissector(buffer, pinfo, tree)
    -- Check if buffer has sufficient length for magic number
    if buffer:len() < MAGIC_LENGTH then
        return 0
    end

    -- Check for magic number in advertisement data
    local magic_offset = find_magic_offset(buffer)

    if not magic_offset then
        return 0
    end

    -- Set protocol in column
    pinfo.cols.protocol = "BLE Lexon x Jeff Koons Balloon Dog Lamp Protocol (Offset: " .. magic_offset .. ")"

    -- Create main subtree
    local subtree = tree:add(proto, buffer(), "Lexon x Jeff Koons Balloon Dog Lamp Data")

    -- Helper function to add field if buffer has enough data
    local function add_field(field_name, proto_field)
        local def = FIELD_DEFS[field_name]
        local abs_offset = magic_offset + def.offset
        if buffer:len() >= abs_offset + def.length then
            subtree:add(proto_field, buffer(abs_offset, def.length))
        end
    end

    -- Parse all fields
    add_field("lamp_group_id", fields.lamp_group_id)
    add_field("unknown1", fields.unknown_bytes1)
    add_field("sequence_id", fields.sequence_id)
    add_field("power_state", fields.power_state)
    add_field("mode", fields.mode)
    add_field("unknown2", fields.unknown_bytes2)
    add_field("brightness", fields.brightness)
    add_field("unknown3", fields.unknown_bytes3)
    add_field("mode_mirror", fields.mode_mirror)
    add_field("effect_direction", fields.effect_direction)
    add_field("effect_breathing_color", fields.effect_breathing_color)
    add_field("effect_fill_color", fields.effect_fill_color)
    add_field("effect_color", fields.effect_color)

    -- All bytes post-magic (everything after magic number for debugging)
    local all_bytes_abs = magic_offset + MAGIC_LENGTH
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

    -- Check for unexpected data length (excluding BTLE CRC)
    local payload_length = buffer:len() - magic_offset - MAGIC_LENGTH - BTLE_CRC_LENGTH
    if payload_length > EXPECTED_LENGTH then
        subtree:add(fields.expected_length,
            "Longer: Payload length (" ..
            payload_length ..
            " bytes) exceeds expected (" .. EXPECTED_LENGTH .. " bytes)")
    elseif payload_length == EXPECTED_LENGTH then
        subtree:add(fields.expected_length, "Yes")
    elseif payload_length < EXPECTED_LENGTH then
        subtree:add(fields.expected_length,
            "Shorter: Payload length (" ..
            payload_length ..
            " bytes) less than expected (" .. EXPECTED_LENGTH .. " bytes)")
    end

    return buffer:len()
end

-- Register the dissector
register_postdissector(proto)
