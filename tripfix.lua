#!/usr/bin/env luajit
local binutil = require("binutil")
local ipfix   = require("ipfix")
local ceil    = math.ceil

local md5     = require("md5")
local mp      = require("MessagePack")
local yaml    = require("yaml")
local rc      = require("redis")
local socket  = require("socket")

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

function round(val, decimal)
  if (decimal) then
    return math.floor( (val * 10^decimal) + 0.5) / (10^decimal)
  else
    return math.floor(val+0.5)
  end
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

local function incr_prefix_ts(prefix,ts,value,redis)
    local key = 'ts:' .. prefix

    if not redis:incrbyfloat(key .. ':' .. ts,value) then
        print("Error incrementing redis counter for " .. key .. ts)
    end

    if not redis:zrank(key,ts) then
        redis:zadd(key,ts,key .. ':' .. ts)
    end
end

local function create_group_statter(name,cfg)
    local name,cfg = name,cfg
    local active_timeout, idle_timeout, slot_length = cfg.active_timeout,cfg.idle_timeout, cfg.slot_length
    local redis = rc.connect('127.0.0.1', 6379)
    return function(flows)
        if not flows then 
            return false
        end
        for i=1,#flows do
            local fields = flows[i]

            -- Retrieve flow start / end from second / millisecond fields
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
            
            local flow_status = fields[136].value

            -- Total flow duration
            local flow_duration = flow_end - flow_start

            if flow_duration == 0 then
                flow_duration = 1 -- Shortest flow duration is 1s
            end

            local observed_duration, observed_start, observed_end = flow_duration,flow_start,flow_end

            if flow_status == 1 then -- This flow has idled to timeout
                -- If flow duration is longer than the idle timeout then this is idle_timeout worth of observations
                if flow_duration > idle_timeout then
                    observed_duration = idle_timeout
                    observed_start = observed_end - idle_timeout
                end
            elseif flow_status == 2 then -- This flow has active timeout
                -- If flow duration is longer than the active timeout then this is active_timeout worth of observations
                if flow_duration > active_timeout then
                    observed_duration = active_timeout
                    observed_start = observed_end - active_timeout
                end
            else -- If this has expired for any other reason we need to work out when the last flow export for this was to calculate the observed_duration
                if flow_duration > idle_timeout and flow_duration > active_timeout then
                    print("This is a long flow and was not active / idle timeout")
                end
            end

            -- Calculate average bps / pps for the observed part of this flow
            local avg_bps = (fields[1].value / observed_duration) * 8
            local avg_pps = fields[2].value / observed_duration

            -- Generate the hash of this flow
            local ff = {
                src_ip   = fields[8].value,  -- srcIP
                src_port = fields[7].value,  -- srcPort
                dst_ip   = fields[12].value, -- dstIP
                dst_port = fields[11].value, -- dstPort
                proto    = fields[4].value,  -- proto
                tos      = fields[5].value,  -- TOS
            }

            local flow_hash = md5.sumhexa(ff.src_ip .. ff.src_port .. ff.dst_ip .. ff.dst_port .. ff.proto ..ff.tos)


            -- Insert flow into redis if it doesnt't already exist
            if not redis:exists(flow_hash) then
                redis:hmset(flow_hash,ff)
            end

            -- Sorted set of existing timestamps referencing keys of secondary set
            -- Secondary set contains values for all data points in each timestamp

            -- Flows are bucketed into slots of slot_length seconds.
            local slots = ""
            local observed_slot_start = observed_start - observed_start % slot_length
            local observed_slot_end = observed_end - observed_end % slot_length
            for t = observed_slot_start, observed_slot_end, slot_length do

                local timeslot = t - t % slot_length

                local slot_start, slot_end = t, t+slot_length

                -- If flow starts after slot starts, adjust slot start forwards
                if observed_start > slot_start then
                    slot_start = observed_start
                end

                -- If flow ends before slot ends, adjust slot end backwards
                if observed_end < slot_end then
                    slot_end = observed_end
                end

                -- Adjust bps / pps based on percentage of flow duration in slot
                local slot_duration = (slot_end - slot_start)
                local slot_fraction = slot_duration / slot_length

                local slot_bps = avg_bps * slot_fraction
                local slot_pps = avg_pps * slot_fraction
               
                -- Don't bother writing to redis if bps or pps is zero
                if slot_bps > 0.0 then
                    incr_prefix_ts(ff.src_ip .. ':out:bps',timeslot,slot_bps,redis)
                    incr_prefix_ts(ff.dst_ip .. ':in:bps',timeslot,slot_bps,redis)
                    incr_prefix_ts('AS' .. fields[16].value .. ':out:bps',timeslot,slot_bps,redis)
                    incr_prefix_ts('AS' .. fields[17].value .. ':in:bps',timeslot,slot_bps,redis)
                end
                if slot_pps > 0.0 then
                    incr_prefix_ts(ff.src_ip .. ':out:pps',timeslot,slot_pps,redis)
                    incr_prefix_ts(ff.dst_ip .. ':in:pps',timeslot,slot_pps,redis)
                    incr_prefix_ts('AS' .. fields[16].value .. ':out:pps',timeslot,slot_pps,redis)
                    incr_prefix_ts('AS' .. fields[17].value .. ':in:pps',timeslot,slot_pps,redis)
                end
            end

            print(flow_hash .. ":: " .. fields[8].value .. ":" .. fields[7].value .. " -> " .. fields[12].value .. ":" .. fields[11].value .. " (" .. round(avg_bps,2) .. "bps / " .. round(avg_pps,2) .. "pps ) - " .. observed_start .. " " .. observed_end .. " : " .. observed_duration .. "s -- ")
--            print(agg.sourceIPv4Address .. ":" .. agg.sourceTransportPort .. " -> " .. agg.destinationIPv4Address .. ":" .. agg.destinationTransportPort .. " (" .. agg.protocolIdentifier .. ") - Bytes: " .. agg.octetDeltaCount .. " Packets: " .. agg.packetDeltaCount .. " Start: " .. agg.flowStartMilliseconds .. " End: " .. (agg.flowEndMilliseconds or '-'))
        end
    end
end


local function create_group_eventer(name,cfg)
    local name,cfg = name,cfg
    local active_timeout, idle_timeout, slot_length = cfg.active_timeout,cfg.idle_timeout, cfg.slot_length
    local redis = rc.connect('127.0.0.1', 6379)
    local last_ran = 0
    return function()
        if last_ran+10 >= os.time() then
            return
        end
        print("Running eventer...")

        -- Get records for AS over time
        local now = os.time()
        local records = redis:zrevrangebyscore('ts:AS0:out:bps',now-active_timeout,now-(2*active_timeout),'withscores')
        if #records > 0 then 
            local first_record_delay = now - records[1][2]
            print("Now is " .. now)
            print("Record delay is approximately " .. first_record_delay .. "s")
            for key,value_key in ipairs(records) do
                local value_key,ts = unpack(value_key)
                local value = redis:get(value_key)
                print(ts .. ": " .. value)
            end
        end
        last_ran = os.time()
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
