local binutil = require("binutil")
local ntob = binutil.ntob
local bton = binutil.bton
local u8   = binutil.u8
local u16  = binutil.u16
local u32  = binutil.u32
local uvar = binutil.uvar

local _M = { templates = {}}

local type_map = {
    unsigned8  = uvar,
    unsigned16 = uvar,
    unsigned32 = uvar,
    unsigned64 = uvar,
    boolean = function (raw) return raw == 1 end,
    ipv4Address = function (raw) return string.format("%i.%i.%i.%i", u8(raw:sub(1)),u8(raw:sub(2)),u8(raw:sub(3)),u8(raw:sub(4))) end,
    default = function (raw) return raw end,
}

function _M.parse_ipfix_value(raw,data_type)
    if type(type_map[data_type]) == 'function' then
        return type_map[data_type](raw)
    else
        return type_map.default()
    end
end


function _M.parse_ipfix_header(packet)
    local header = {
        ver   = uvar(packet:sub(1,2)),
        len   = uvar(packet:sub(3,4)),
        ts    = uvar(packet:sub(5,8)),
        hrts  = os.date("%c", ts),
        seq   = uvar(packet:sub(9,12)),
        domid = uvar(packet:sub(13,16)),
    }
    return header, packet:sub(17)
end


function _M.parse_ipfix_set(packet)
    local set = {
        id    = uvar(packet:sub(1,2)),
        len   = uvar(packet:sub(3,4)),
    }

    local set_data = packet:sub(5,set.len)

    if set.id == 2 then -- If this is a template set then parse as such
        set.tpl_id = uvar(set_data:sub(1,2))
        set.no_fields = uvar(set_data:sub(3,4))

        local fields = {}
        
        set_data = set_data:sub(5)

        -- For each field, pull type and length
        for i=1,set.no_fields do
            local typ = uvar(set_data:sub(1,2))
            local len = uvar(set_data:sub(3,4))
            local enterprise_id = nil
            if typ >= 32768 then -- If enterprise bit is set
                enterprise_id = uvar(set_data:sub(5,8))
                typ = typ - 32768
                set_data = set_data:sub(9)
            else
                set_data = set_data:sub(5)
            end

            local vars = elements[typ] or {}

            local name
            if enterprise_id == 29305 then -- This is a reverse
                name = vars.name .. 'Reverse'
            else
                name = vars.name
            end

            local field = {
                typ = typ,
                name = name or 'Unknown',
                data_type = vars.data_type or 'unknown',
                data_semantic = vars.data_semantic or 'unknown',
                data_unit = vars.unit or 'unknown',
                enterprise_id = enterprise_id or 0,
                len = len,
            }
            fields[#fields+1] = field
        end
        set.fields = fields
        _M.templates[set.tpl_id] = set
    elseif set.id == 3 then -- If this is an options template, ignore for the moment

    elseif set.id >= 4 and set.id <= 255 then
        -- Ignore, these are unassigned
    else
        -- Template ID is our set.id
        local template = _M.templates[set.id]
        if not template then
            print("Identified set with template ID " .. set.id .. " we don't have cached yet...")
        else
            local fields = template.fields
            local flows = {}
            -- While we still have data left
            while #set_data > 0 do
                -- Instantiate a new flow
                local flow = {}

                -- For our template fields, 
                for i=1,#fields do
                    local field = fields[i]
                    local field_len = field.len
                    local data_type = field.data_type
                    local raw_value = set_data:sub(1,field_len)
                    local value = _M.parse_ipfix_value(raw_value,data_type)
                    field.raw_value = raw_value
                    field.value = value
                    flow[#flow+1] = field
                    set_data = set_data:sub(field_len+1)
                end
                flows[#flows+1] = flow
            end
            set.flows = flows
        end

    end

    return set, packet:sub(set.len+1)
end

return _M
