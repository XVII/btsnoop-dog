-- Wireshark BLE Advertisement Data Dissector for Lexon x Jeff Koons Balloon Dog Lamp Protocol
-- Dissects BLE advertisement data emitted by the device
-- Reverse engineered by analyzing captured packets with the help of AI

-- Create a new protocol
local proto        = Proto("btle_lxjkbdla", "BLE Lexon x Jeff Koons Balloon Dog Lamp Protocol")

local MAGIC_NUMBER     = { 0x21, 0x48, 0x52, 0x52, 0x46 }
local MAGIC_LENGTH     = #MAGIC_NUMBER

local FIELD_DEFS = {
    {
        name   = "lamp_group_id",
        offset = MAGIC_LENGTH,
        length = 6,
        field  = ProtoField.bytes(proto.name .. ".lamp_group_id", "Lamp Group ID", base.COLON)
    },
    {
        name   = "unknown1",
        offset = MAGIC_LENGTH + 6,
        length = 2,
        field  = ProtoField.bytes(proto.name .. ".unknown_bytes1", "Unknown Bytes 1", base.COLON)
    },
    {
        name   = "sequence_id",
        offset = MAGIC_LENGTH + 8,
        length = 1,
        field  = ProtoField.uint8(proto.name .. ".sequence_id", "Sequence ID (0-255)", base.DEC)
    },
    {
        name   = "power_state",
        offset = MAGIC_LENGTH + 9,
        length = 1,
        field  = ProtoField.uint8(proto.name .. ".power_state", "Power State", base.DEC, { [0] = "Off", [1] = "On" })
    },
    {
        name   = "mode",
        offset = MAGIC_LENGTH + 10,
        length = 1,
        field  = ProtoField.uint8(proto.name .. ".mode", "Mode", base.DEC, {
            [0] = "Solid Color", [1] = "Sunset", [2] = "Rainbow Flow", [3] = "Fill", [4] = "Knight Rider",
            [5] = "Rainbow Cycle", [6] = "Slow Flow", [7] = "Breathing Rainbow Cycle", [8] = "Chase Solid",
            [9] = "Strobe", [10] = "Segment"
        })
    },
    {
        name   = "unknown2",
        offset = MAGIC_LENGTH + 11,
        length = 4,
        field  = ProtoField.bytes(proto.name .. ".unknown_bytes2", "Unknown Bytes 2", base.COLON)
    },
    {
        name   = "brightness",
        offset = MAGIC_LENGTH + 15,
        length = 2,
        field  = ProtoField.uint16(proto.name .. ".brightness", "Brightness", base.DEC)
    },
    {
        name   = "unknown3",
        offset = MAGIC_LENGTH + 17,
        length = 5,
        field  = ProtoField.bytes(proto.name .. ".unknown_bytes3", "Unknown Bytes 3", base.COLON)
    },
    {
        name   = "mode_mirror",
        offset = MAGIC_LENGTH + 22,
        length = 1,
        field  = ProtoField.uint8(proto.name .. ".mode_mirror", "Mode Mirror", base.DEC, {
            [0] = "Solid Color", [1] = "Sunset", [2] = "Rainbow Flow", [3] = "Fill", [4] = "Knight Rider",
            [5] = "Rainbow Cycle", [6] = "Slow Flow", [7] = "Breathing Rainbow Cycle", [8] = "Chase Solid",
            [9] = "Strobe", [10] = "Segment"
        })
    },
    {
        name   = "effect_direction",
        offset = MAGIC_LENGTH + 23,
        length = 1,
        field  = ProtoField.bytes(proto.name .. ".effect_direction", "Effect Direction", base.NONE)
    },
    {
        name   = "effect_breathing_color",
        offset = MAGIC_LENGTH + 24,
        length = 1,
        field  = ProtoField.uint8(proto.name .. ".effect_breathing_color", "Breathing Color", base.DEC, {
            [0] = "Red", [1] = "Green", [2] = "Blue", [3] = "Yellow", [4] = "Purple",
            [5] = "Cyan", [6] = "Cool White", [7] = "Warm Yellow", [8] = "Pink"
        })
    },
    {
        name   = "effect_fill_color",
        offset = MAGIC_LENGTH + 25,
        length = 1,
        field  = ProtoField.uint8(proto.name .. ".effect_fill_color", "Fill Color", base.DEC,
            { [0] = "0", [1] = "1", [2] = "2", [3] = "3", [4] = "4", [5] = "5", [6] = "6", [7] = "7", [8] = "8" })
    },
    {
        name   = "effect_color",
        offset = MAGIC_LENGTH + 26,
        length = 1,
        field  = ProtoField.uint8(proto.name .. ".effect_color", "Effect Color", base.DEC, {
            [0] = "Cool White", [1] = "Warm White", [2] = "Blue", [3] = "Orange", [4] = "Purple",
            [5] = "Pink", [6] = "Red", [7] = "Yellow", [8] = "Green"
        })
    },
}

local BTLE_CRC_LENGTH  = 3  -- BTLE CRC at end of packet

-- Calculate expected payload length from field definitions
local EXPECTED_LENGTH = 0
for _, def in ipairs(FIELD_DEFS) do
    EXPECTED_LENGTH = EXPECTED_LENGTH + def.length
end

-- Register all fields with the protocol
local fields = proto.fields
for _, def in ipairs(FIELD_DEFS) do
    table.insert(fields, def.field)
end

-- Additional debug/utility fields
fields.payload_bytes = ProtoField.bytes(proto.name .. ".payload_bytes", "Payload Bytes", base.COLON)
fields.payload_index = ProtoField.bytes(proto.name .. ".payload_index", "   Byte Index", base.COLON)
fields.expected_length = ProtoField.string(proto.name .. ".expected_length", "Expected Length", base.NONE)


-- Fixed offset where magic number should appear
local MAGIC_OFFSET = 0x20  -- 32 decimal

-- Function to check if bytes match magic number at fixed offset
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
    -- Check if buffer has sufficient length for magic number at fixed offset
    if buffer:len() < MAGIC_OFFSET + MAGIC_LENGTH then
        return 0
    end

    -- Check for magic number at fixed offset 0x20
    if not check_magic_number(buffer, MAGIC_OFFSET) then
        return 0
    end

    -- Set protocol in column
    pinfo.cols.protocol = "BLE Lexon x Jeff Koons Balloon Dog Lamp Protocol"

    -- Create main subtree
    local subtree = tree:add(proto, buffer(), "Lexon x Jeff Koons Balloon Dog Lamp Data")

    -- Parse all fields using unified definitions
    for _, def in ipairs(FIELD_DEFS) do
        local abs_offset = MAGIC_OFFSET + def.offset
        if buffer:len() >= abs_offset + def.length then
            subtree:add(def.field, buffer(abs_offset, def.length))
        end
    end

    -- Payload bytes post-magic (everything after magic number for debugging)
    local payload_bytes_abs = MAGIC_OFFSET + MAGIC_LENGTH
    if buffer:len() > payload_bytes_abs + BTLE_CRC_LENGTH then
        local payload_bytes = buffer(payload_bytes_abs, buffer:len() - payload_bytes_abs - BTLE_CRC_LENGTH)
        subtree:add(fields.payload_bytes, payload_bytes)

        -- Add indexed bytes
        local idx_len = payload_bytes:len()
        if idx_len > 0 then
            local idx_hex = {}
            for i = 0, idx_len - 1 do
                idx_hex[i + 1] = string.format("%02x", i)
            end
            local idx_ba = ByteArray.new(table.concat(idx_hex))
            local idx_tvb = idx_ba:tvb("Ref_IndexBytes")
            subtree:add(fields.payload_index, idx_tvb(0, idx_len))
        end
    end

    -- Check for unexpected data length (excluding BTLE CRC)
    local payload_length = buffer:len() - MAGIC_OFFSET - MAGIC_LENGTH - BTLE_CRC_LENGTH
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
