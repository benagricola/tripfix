#!/usr/bin/env luajit
local binutil = require("binutil")
local ipfix   = require("ipfix")
local ceil = math.ceil

local yaml = require("yaml")
local socket = require("socket")

local f,err = io.open("./tripfix.yaml", "r")
config = yaml.load(f:read("*all"))
f:close()

local f,err = io.open("./iana_dict.yaml", "r")
constants = yaml.load(f:read("*all"))
elements = constants.elements
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

        local header, packet = ipfix.parse_header(packet)
        parsed.header = header

        -- Parse packet sets while we still have some
        local flows = {}
        while #packet > 0 do
            set, packet = ipfix.parse_set(packet)
            
            -- If this is a template set, then set its' template id in global templates
            if set.id == 2 then
            -- Otherwise this is an options template set, skip for now

            elseif set.id == 3 then
                print("Options template detected, ignoring...")

            -- Otherwise add it to the table of sets to be used for flow records
            else
                local new_flows = set.flows
                if not new_flows then
                    return false
                end
                for i=1,#new_flows do
                    flows[#flows+1] = new_flows[i]
                end
            end
        end
        return flows
    end
end

local function create_group_statter(name,cfg)
    local name,cfg = name,cfg
    return function(flows)
        if not flows then 
            return false
        end
        for i=1,#flows do
            local fields = flows[i]
            local flow_start,flow_end, flow_duration
            if fields[150] and fields[151] then
                flow_start = fields[150].value
                flow_end   = fields[151].value
            elseif fields[152] and fields[153] then
                flow_start = ceil(fields[152].value / 1000)
                flow_end   = ceil(fields[153].value / 1000)
            else
                print("Flow packet with no identifiable flow start / end")
                
            end

            local flow_duration = flow_end - flow_start
            local flow_status = fields[136].value
            local status_text
            if flow_status == 1 then
                status_text = 'idle timeout'
            elseif flow_status == 2 then
                status_text = 'active timeout'
            elseif flow_status == 3 then
                status_text = 'finished'
            elseif flow_status == 4 then
                status_text = 'terminated'
            elseif flow_status == 5 then
                status_text = 'lack_of_resources'
            end

            print(fields[1].value .. " = " .. fields[8].value .. ":" .. fields[7].value .. " -> " .. fields[12].value .. ":" .. fields[11].value .. " - " .. flow_start .. " " .. flow_end .. " : " .. flow_duration .. " - " .. status_text)
--            print(agg.sourceIPv4Address .. ":" .. agg.sourceTransportPort .. " -> " .. agg.destinationIPv4Address .. ":" .. agg.destinationTransportPort .. " (" .. agg.protocolIdentifier .. ") - Bytes: " .. agg.octetDeltaCount .. " Packets: " .. agg.packetDeltaCount .. " Start: " .. agg.flowStartMilliseconds .. " End: " .. (agg.flowEndMilliseconds or '-'))
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

ipfix.configure(config,elements)
ipfix.load_templates()

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
