local str_byte      = string.byte
local str_char      = string.char
local bit_lshift    = bit.lshift
local bit_rshift    = bit.rshift
local bit_band      = bit.band
local tbl_concat    = table.concat
local ipairs        = ipairs

local _M = {}

-- Number to binary. Converts a lua number into binary string with <bytes> bytes (8 max)
function _M.ntob(num,bytes)
    bytes = bytes or 1

    local str = ""

    -- Mask high bit
    local mask = bit_lshift(0xff,(bytes-1)*8)

    for i=1, bytes do
        -- Isolate current bit by anding it with mask, then shift it bytes-i right
        -- This puts it into byte '0'.
        local val = bit_rshift(bit_band(num,mask),(bytes-i)*8)
        -- Pass it to str_char and append to string
        str = str .. str_char(val)
        -- Shift the mask 1 byte to the left and repeat
        mask = bit_rshift(mask,8)
    end
    return str
end

function _M.bton(str)
    local num = 0
    local bytes = {str_byte(str,1,#str)}

    for i=1, #bytes do
        num = bit_lshift(num,8) + bit_band(bytes[i],0xff)
    end
    return num
end

--- Get an 8-bit integer at a 0-based byte offset in a byte string.
-- @param b A byte string.
-- @param i Offset.
-- @return An 8-bit integer.
function _M.u8(b)
  return string.byte(b, 1)
end

--- Get a 16-bit integer at a 0-based byte offset in a byte string.
-- @param b A byte string.
-- @param i Offset.
-- @return A 16-bit integer.
function _M.u16(b)
  local b1,b2
  b1, b2 = string.byte(b, 1), string.byte(b, 2)
  --        2^8     2^0
  return b1*256 + b2
end

--- Get a 32-bit integer at a 0-based byte offset in a byte string.
-- @param b A byte string.
-- @param i Offset.
-- @return A 32-bit integer.
function _M.u32(b)
  local b1,b2,b3,b4
  b1, b2 = string.byte(b, 1), string.byte(b, 2)
  b3, b4 = string.byte(b, 3), string.byte(b, 4)
  --        2^24          2^16       2^8     2^0
  return b1*16777216 + b2*65536 + b3*256 + b4
end

function _M.u64(b)
  local b1,b2,b3,b4,b5,b6,b7,b8
  b1, b2 = string.byte(b, 1), string.byte(b, 2)
  b3, b4 = string.byte(b, 3), string.byte(b, 4)
  b5, b6 = string.byte(b, 5), string.byte(b, 6)
  b7, b8 = string.byte(b, 7), string.byte(b, 8)
  --        2^24          2^16       2^8     2^0
  return b1*(2^56) + b2*(2^48) + b3*(2^40) + b4*(2^32) + b5*(2^24) + b6*(2^16) + b7*(2^8) + b8
end

function _M.uvar(b)
    if #b == 1 then
        return _M.u8(b)
    elseif #b == 2 then
        return _M.u16(b)
    elseif #b == 4 then
        return _M.u32(b)
    elseif #b == 8 then
        return _M.u64(b)
    end
end

return _M
