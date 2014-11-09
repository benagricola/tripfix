#!/usr/bin/env luajit
local binutil = require("binutil")
local ntob = binutil.ntob
local bton = binutil.bton
local yaml = require("yaml")
local socket = require("socket")

local f,err = io.open("./tripfix.yaml", "r")
config = yaml.load(f:read("*all"))
f:close()

local f,err = io.open("./iana_dict.yaml", "r")
elements = yaml.load(f:read("*all"))
f:close()


function rPrint(s, l, i) -- recursive Print (structure, limit, indent)
    l = (l) or 500; i = i or "";        -- default item limit, indent string
    if (l<1) then print "ERROR: Item limit reached."; return l-1 end;
    local ts = type(s);
    if (ts ~= "table") then print (i,ts,s); return l-1 end
    print (i,ts);           -- print "table"
    for k,v in pairs(s) do  -- print "[KEY] VALUE"
        l = rPrint(v, l, i.."\t["..tostring(k).."]");
        if (l < 0) then break end
    end
    return l
end     


local function parse_ipfix_header(packet)
    local header = {
        ver   = bton(packet:sub(1,2)),
        len   = bton(packet:sub(3,4)),
        ts    = bton(packet:sub(5,8)),
        hrts  = os.date("%c", ts),
        seq   = bton(packet:sub(9,12)),
        domid = bton(packet:sub(13,16)),
    }
    return header, packet:sub(17)
end

local function parse_ipfix_set(packet)
    local set = {
        id    = bton(packet:sub(1,2)),
        len   = bton(packet:sub(3,4)),
    }

    if set.id == 2 then -- If this is a template set then parse as such
        set.tpl_id = bton(packet:sub(5,6))
        set.no_fields = bton(packet:sub(7,8))

        local fields = {}
        local fdata = packet:sub(9)
        for i=0,set.no_fields do
            local offset = (i*4)+1
            local typ = bton(fdata:sub(offset,offset+1))
            local vars = elements[typ] or {}
            local field = {
                typ = typ,
                name = vars.name or 'Unknown',
                data_type = vars.data_type or 'unknown',
                data_semantic = vars.data_semantic or 'unknown',
                data_unit = vars.unit or 'unknown',
                len = bton(fdata:sub(offset+2,offset+3)),
            }
            fields[#fields+1] = field
        end
        set.fields = fields
        rPrint(set)
    end

    return set, packet:sub(set.len+1)
end

local function create_group_listener(name,cfg)
    local name,sources,sinks,thresholds = name,cfg.sources,cfg.sinks,cfg.thresholds
    local listen_host,listen_port = cfg.listen_host,cfg.listen_port

    -- Setup listening socket for group
    local sock = socket.udp()
    print("Group " .. name .. " listening on " .. listen_host .. ":" .. listen_port)
    sock:setsockname(listen_host,tonumber(listen_port))
    sock:settimeout(0.1) -- Set a nonzero timeout - we don't want to hotloop
    return function()
        local packet, host, port, err = sock:receivefrom()
        if not packet then -- No packets ready to be received - do nothing
            return false
        end
        -- Parse recieved packet header
        local parsed = {}

        local header, packet = parse_ipfix_header(packet)
        parsed.header = header
        local sets = {}
        while #packet > 0 do
            set, packet = parse_ipfix_set(packet)
            sets[#sets+1] = set
        end
        parsed.sets = sets
    end
end
local function create_group_statter(name,cfg)
    local name,cfg = name,cfg
    return function()
       --io.write("Statter") 
    end
end
local function create_group_eventer(name,cfg)
    local name,cfg = name,cfg
    return function()
       --io.write("Eventer") 
    end
end
local function create_group_sender(name,cfg)
    return function()
       --io.write("Sender") 
    end
end

local groups = {}

for grpname,grpcfg in pairs(config.groups or {}) do
    local steps = {}
    steps[#steps+1] = create_group_listener(grpname,grpcfg)
    steps[#steps+1] = create_group_statter(grpname,grpcfg)
    steps[#steps+1] = create_group_eventer(grpname,grpcfg)
    steps[#steps+1] = create_group_sender(grpname,grpcfg)
    groups[#groups+1] = steps
end

while true do
    for i=1,#groups do
        local steps = groups[i]
        for j=1,#steps do
            local step = steps[j]
            step()
        end
    end
end 
