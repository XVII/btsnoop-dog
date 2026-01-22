-- Wireshark BLE Advertisement Data Dissector for Lexon x Jeff Koons Balloon Dog Protocol
-- Dissects BLE advertisement data emitted by the Balloon Dog device

-- Create a new protocol
local ble_lxjkbd = Proto("ble_lxjkbd", "BLE Lexon x Jeff Koons Balloon Dog Lamp Protocol")

-- Define protocol fields
local fields = ble_lxjkbd.fields

-- Duplicate tracking fields
fields.message_id = ProtoField.bytes("ble_lxjkbd.message_id", "Message ID", base.NONE)
fields.message_status = ProtoField.string("ble_lxjkbd.message_status", "Message Status", base.NONE)

-- Guessed fields
fields.expected_length = ProtoField.string("ble_lxjkbd.expected_length", "Expected Length", base.NONE)
fields.lamp_group_id = ProtoField.bytes("ble_lxjkbd.lamp_group_id", "Lamp Group ID", base.COLON)
fields.sequence_id = ProtoField.uint8("ble_lxjkbd.sequence_id", "Sequence ID (0-255)", base.DEC)

fields.all_bytes_post_magic = ProtoField.bytes("ble_lxjkbd.all_bytes_post_magic", "All Bytes Post-Magic", base.COLON)

-- Define the magic number and offsets (all offsets relative to MAGIC_OFFSET)
local MAGIC_NUMBER = { 0x21, 0x48, 0x52, 0x52, 0x46 }
local MAGIC_LENGTH = #MAGIC_NUMBER
local MAGIC_OFFSET = 32 -- absolute offset in packet

-- Offsets relative to MAGIC_OFFSET
local LAMP_GROUP_ID_OFFSET = MAGIC_LENGTH  -- immediately after magic
local LAMP_GROUP_ID_LENGTH = 6
local SEQUENCE_ID_OFFSET = MAGIC_LENGTH + LAMP_GROUP_ID_LENGTH + 2  -- 2 unknown bytes after lamp group
local SEQUENCE_ID_LENGTH = 1
local MESSAGE_ID_OFFSET = 64 - MAGIC_OFFSET  -- convert absolute byte 64 to relative
local MESSAGE_ID_LENGTH = 3
local EXPECTED_LENGTH = 67 - MAGIC_OFFSET  -- relative to magic start

local function get_field_offset(relative_offset)
    return MAGIC_OFFSET + relative_offset
end

-- Track all seen Message IDs to flag duplicates regardless of order
local seen_message_ids = {}
local frame_message_status = {}

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

    -- All bytes post-magic (everything after magic number for debugging)
    local all_bytes_post_magic_abs = get_field_offset(MAGIC_LENGTH)
    if buffer:len() > all_bytes_post_magic_abs then
        subtree:add(fields.all_bytes_post_magic, buffer(all_bytes_post_magic_abs, buffer:len() - all_bytes_post_magic_abs))
    end

    -- Message ID Parsing and Duplicate Detection
    local message_status_text = "Missing"
    local message_id_hex = nil

    local message_id_abs = get_field_offset(MESSAGE_ID_OFFSET)
    if buffer:len() >= message_id_abs + MESSAGE_ID_LENGTH then
        local message_id_bytes = buffer(message_id_abs, MESSAGE_ID_LENGTH)
        message_id_hex = range_to_hex(message_id_bytes)

        -- Only mutate caches on first visit; Wireshark calls dissectors multiple times
        if not pinfo.visited then
            local is_duplicate = seen_message_ids[message_id_hex] == true
            if is_duplicate then
                message_status_text = "Seen"
            else
                message_status_text = "New"
                seen_message_ids[message_id_hex] = true
            end
            frame_message_status[pinfo.number] = message_status_text
        else
            message_status_text = frame_message_status[pinfo.number] or "Seen"
        end

        subtree:add(fields.message_id, message_id_bytes)
    else
        message_status_text = "Missing"
    end

    subtree:add(fields.message_status, message_status_text)

    -- Check for unexpected data length
    local expected_abs = get_field_offset(EXPECTED_LENGTH)
    if buffer:len() > expected_abs then
        subtree:add(fields.expected_length,
            "Longer: Buffer length (" ..
            buffer:len() .. " bytes) exceeds expected (" .. expected_abs .. " bytes) - possibly an undiscovered format variant")
    elseif buffer:len() == expected_abs then
        subtree:add(fields.expected_length, "Standard")
    elseif buffer:len() < expected_abs then
        subtree:add(fields.expected_length,
            "Shorter: Buffer length (" ..
            buffer:len() .. " bytes) less than expected (" .. expected_abs .. " bytes) - possibly an undiscovered format variant")
    end

    return buffer:len()
end

-- Register the dissector
register_postdissector(ble_lxjkbd)
