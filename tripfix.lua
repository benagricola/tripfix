#!/usr/bin/env luajit
local binutil = require("binutil")
local ipfix   = require("ipfix")

local ntob = binutil.ntob
local u8   = binutil.u8
local u16  = binutil.u16
local u32  = binutil.u32
local uvar = binutil.uvar

local yaml = require("yaml")
local socket = require("socket")

local f,err = io.open("./tripfix.yaml", "r")
config = yaml.load(f:read("*all"))
f:close()

local f,err = io.open("./iana_dict.yaml", "r")
constants = yaml.load(f:read("*all"))
elements = constants.elements
f:close()


local function load_templates()
    local f,err = io.open("./template_cache.yaml", "r")
    if not f then return end
    templates = yaml.load(f:read("*all"))
    ipfix.templates = templates
    f:close()
end

local function save_templates()
    local f,err = io.open("./template_cache.yaml", "w")
    f:write(yaml.dump(ipfix.templates))
    f:close()
end

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



local function create_group_listener(name,cfg)
    local name,sources,sinks,thresholds = name,cfg.sources,cfg.sinks,cfg.thresholds
    local listen_host,listen_port = cfg.listen_host,cfg.listen_port

    -- Setup listening socket for group
    local sock = socket.udp()
    print("Group " .. name .. " listening on " .. listen_host .. ":" .. listen_port)
    sock:setsockname(listen_host,tonumber(listen_port))
    sock:settimeout(0.1) -- Set a nonzero timeout - we don't want to hotloop
    return function(ret)
        local packet, host, port, err = sock:receivefrom()
        if not packet then -- No packets ready to be received - do nothing
            return false
        end
        -- Parse recieved packet header
        local parsed = {}

        local header, packet = ipfix.parse_ipfix_header(packet)
        parsed.header = header

        -- Parse packet sets while we still have some
        local flows = {}
        while #packet > 0 do
            set, packet = ipfix.parse_ipfix_set(packet)
            
            -- If this is a template set, then set its' template id in global templates
            if set.id == 2 then
                save_templates()
            -- Otherwise this is an options template set, skip for now
            elseif set.id == 3 then
                print("Options template detected, ignoring...")

            -- Otherwise add it to the table of sets to be used for flow records
            else
                flows[#flows+1] = set.flows
            end
        end
        return flows
    end
end

local function create_group_statter(name,cfg)
    local name,cfg = name,cfg
    return function(sets)
        if not sets then 
            return false
        end
        for h=1,#sets do
            local set = sets[h]
            for i=1,#sets do
                local fields = set[i]
                local agg = {}
                for j=1,#fields do
                    local field = fields[j]
                    agg[field.name] = field.value
                end
                print(agg.sourceIPv4Address .. ":" .. agg.sourceTransportPort .. " -> " .. agg.destinationIPv4Address .. ":" .. agg.destinationTransportPort .. " (" .. agg.protocolIdentifier .. ") - Bytes: " .. agg.octetDeltaCount .. " Packets: " .. agg.packetDeltaCount)
            end
        end
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

load_templates()

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
        local ret
        for j=1,#steps do
            local step = steps[j]
            ret = step(ret)
        end
    end
end 
