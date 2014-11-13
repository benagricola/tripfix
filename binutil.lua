local str_byte      = string.byte

local _M = {}

function _M.u8(b)
  return str_byte(b, 1)
end

function _M.u16(b)
  local b1,b2
  b1, b2 = str_byte(b, 1), str_byte(b, 2)
  --        2^8     2^0
  return b1*256 + b2
end

function _M.u32(b)
  local b1,b2,b3,b4
  b1, b2 = str_byte(b, 1), str_byte(b, 2)
  b3, b4 = str_byte(b, 3), str_byte(b, 4)
  --        2^24          2^16       2^8     2^0
  return b1*16777216 + b2*65536 + b3*256 + b4
end

function _M.u64(b)
  local b1,b2,b3,b4,b5,b6,b7,b8
  b1, b2 = str_byte(b, 1), str_byte(b, 2)
  b3, b4 = str_byte(b, 3), str_byte(b, 4)
  b5, b6 = str_byte(b, 5), str_byte(b, 6)
  b7, b8 = str_byte(b, 7), str_byte(b, 8)
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
