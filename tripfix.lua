#!/usr/bin/env luajit
local binutil = require("binutil")
local ipfix   = require("ipfix")
local ceil    = math.ceil

local md5     = require("md5")
local mp      = require("MessagePack")
local yaml    = require("yaml")
local rc      = require("redis")
local socket  = require("socket")

ProFi = require 'ProFi'
ProFi:start()

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
function interp(s, tab)
    return (s:gsub('($%b{})', function(w) return tab[w:sub(3, -2)] or "N/A" end))
end


-- Initialise tables used to hold various statistics
local host_stats,subnet_stats,as_stats,hostport_stats,protocol_stats = {},{},{},{},{}


local function create_group_listener(name,cfg)
    local group_cfg = cfg.groups[name]
    local name,sources,sinks,thresholds = name,group_cfg.sources,group_cfg.sinks,group_cfg.thresholds
    local listen_host,listen_port = group_cfg.listen_host,group_cfg.listen_port

    -- Setup listening socket for group
    local sock = socket.udp()
    print("Group " .. name .. " listening on " .. listen_host .. ":" .. listen_port)
    sock:setsockname(listen_host,tonumber(listen_port))
    sock:settimeout(0.01) -- Set a nonzero timeout - we don't want to hotloop
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

local function store_counter(tbl,timeslot,key,metric,direction,value)
    -- Make sure key is always a string
    key = tostring(key)

    -- If timeslot doesn't exist, create it
    if not tbl[timeslot] then
        tbl[timeslot] = {}
    end
    if not tbl[timeslot][key] then
        tbl[timeslot][key] = { 
            inbound  = {}, 
            outbound = {},
        }
    end

    if not tbl[timeslot][key][direction][metric] then
        tbl[timeslot][key][direction][metric] = value
    else
        tbl[timeslot][key][direction][metric] = tbl[timeslot][key][direction][metric] + value
    end
end

local function get_counter(tbl,timeslot,key,metric,direction)
    local slot_f, stat_f, dir_f, stat = tbl[timeslot], nil, nil, 0
    if slot_f then
        stat_f = slot_f[tostring(key)]
        if stat_f then
            dir_f = stat_f[direction]
            if dir_f then 
                stat = dir_f[metric]
            end
        end
    end
    if not stat then
        stat = 0
    end
    return stat
end

local function get_timeslots(tbl,time_start,time_end,slot_length,key,metric,direction)
    local timeslot_start = time_start - time_start % slot_length
    local timeslot_end = time_end - time_end % slot_length
    local out = {}
    for timeslot = timeslot_start, timeslot_end, slot_length do
        out[#out+1] = {timeslot,get_counter(tbl,timeslot,key,metric,direction)}
    end
    return out
end

local graph_socket = socket.udp()
local function graph_counter(graphite_host,graphite_port,timeslot,path,key,metric,direction,value)
    -- Make sure key is always a string
    key = tostring(key)
    local path = table.concat({
        'ipfix',
        path,
        key:gsub("%.","-"),
        direction,
        metric,
    },".")

    local packet = table.concat({
        path,
        round(value,2),
        timeslot,
    }," ")

    -- print("Sending packet to " .. graphite_host .. ":" .. graphite_port .. "\n" ..packet)
    graph_socket:sendto(packet,graphite_host,graphite_port)

end

local function create_group_statter(name,cfg)
    local group_cfg = cfg.groups[name]
    local active_timeout, idle_timeout, slot_length, local_as = group_cfg.active_timeout,group_cfg.idle_timeout, group_cfg.slot_length, group_cfg.local_as
    local graphite_host,graphite_port = group_cfg.graphite_host, group_cfg.graphite_port
    local ip_ranges = cfg.ip_ranges
    local interesting_ports = {}
    for i=1, #group_cfg.interesting_ports, 1 do
        interesting_ports[group_cfg.interesting_ports[i]] = true
    end

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
                src_ip   = fields[8].value[1],  -- srcIPString
                src_ipno = fields[8].value[2],  -- srcIPNumber
                src_port = fields[7].value,     -- srcPort
                dst_ip   = fields[12].value[1], -- dstIPString
                dst_ipno = fields[12].value[2], -- dstIPNumber
                dst_port = fields[11].value,    -- dstPort
                proto    = fields[4].value,     -- proto
                tos      = fields[5].value,     -- TOS
            }

            local flow_hash = md5.sumhexa(ff.src_ip .. ff.src_port .. ff.dst_ip .. ff.dst_port .. ff.proto ..ff.tos)

            ff.src_as         = fields[16].value
            ff.dst_as         = fields[17].value 
            if ff.src_as == 0 then
                ff.src_as = local_as
            end
            if ff.dst_as == 0 then
                ff.dst_as = local_as
            end
            ff.src_hostport   = ff.src_ip .. ':' .. ff.src_port
            ff.dst_hostport   = ff.dst_ip .. ':' .. ff.dst_port

            for range_name, subnets in ipairs(ip_ranges) do
                print(range_name)
            end

            -- Insert flow into redis if it doesnt't already exist
            -- if not redis:exists(flow_hash) then
            --     redis:hmset(flow_hash,ff)
            -- end

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
                local slot_fps = (1 / slot_length) * slot_fraction

                -- Set Statistics in table
                -- host_stats,subnet_stats,as_stats,hostport_stats,protocol_stats
               
                -- Source host outbound counters
                store_counter(host_stats,timeslot,ff.src_ipno,'pps','outbound',slot_pps)
                store_counter(host_stats,timeslot,ff.src_ipno,'bps','outbound',slot_bps)
                store_counter(host_stats,timeslot,ff.src_ipno,'fps','outbound',slot_fps)
                graph_counter(graphite_host,graphite_port,timeslot,'host',ff.src_ip,'pps','outbound',slot_pps)
                graph_counter(graphite_host,graphite_port,timeslot,'host',ff.src_ip,'bps','outbound',slot_bps)
                graph_counter(graphite_host,graphite_port,timeslot,'host',ff.src_ip,'fps','outbound',slot_fps)

                -- Dest host inbound counters
                store_counter(host_stats,timeslot,ff.dst_ipno,'pps','inbound',slot_pps)
                store_counter(host_stats,timeslot,ff.dst_ipno,'bps','inbound',slot_bps)
                store_counter(host_stats,timeslot,ff.dst_ipno,'fps','inbound',slot_fps)
                graph_counter(graphite_host,graphite_port,timeslot,'host',ff.dst_ip,'pps','inbound',slot_pps)
                graph_counter(graphite_host,graphite_port,timeslot,'host',ff.dst_ip,'bps','inbound',slot_bps)
                graph_counter(graphite_host,graphite_port,timeslot,'host',ff.dst_ip,'fps','inbound',slot_fps)

                -- Only store hostport data for 'interesting' ports
                if interesting_ports[ff.src_port] then
                    -- Source hostport outbound counters
                    store_counter(hostport_stats,timeslot,ff.src_hostport,'pps','outbound',slot_pps)
                    store_counter(hostport_stats,timeslot,ff.src_hostport,'bps','outbound',slot_bps)
                    store_counter(hostport_stats,timeslot,ff.src_hostport,'fps','outbound',slot_fps) 
                    graph_counter(graphite_host,graphite_port,timeslot,'hostport',ff.src_hostport,'pps','outbound',slot_pps)
                    graph_counter(graphite_host,graphite_port,timeslot,'hostport',ff.src_hostport,'bps','outbound',slot_bps)
                    graph_counter(graphite_host,graphite_port,timeslot,'hostport',ff.src_hostport,'fps','outbound',slot_fps)
                end

                -- Only store hostport data for 'interesting' ports
                if interesting_ports[ff.dst_port] then
                    -- Dest hostport inbound counters
                    store_counter(hostport_stats,timeslot,ff.dst_hostport,'pps','inbound',slot_pps)
                    store_counter(hostport_stats,timeslot,ff.dst_hostport,'bps','inbound',slot_bps)
                    store_counter(hostport_stats,timeslot,ff.dst_hostport,'fps','inbound',slot_fps)
                    graph_counter(graphite_host,graphite_port,timeslot,'hostport',ff.dst_hostport,'pps','inbound',slot_pps)
                    graph_counter(graphite_host,graphite_port,timeslot,'hostport',ff.dst_hostport,'bps','inbound',slot_bps)
                    graph_counter(graphite_host,graphite_port,timeslot,'hostport',ff.dst_hostport,'fps','inbound',slot_fps)
                end

                -- Source AS outbound counters
                store_counter(as_stats,timeslot,ff.src_as,'pps','outbound',slot_pps)
                store_counter(as_stats,timeslot,ff.src_as,'bps','outbound',slot_bps)
                store_counter(as_stats,timeslot,ff.src_as,'fps','outbound',slot_fps)
                graph_counter(graphite_host,graphite_port,timeslot,'as-number',ff.src_as,'pps','outbound',slot_pps)
                graph_counter(graphite_host,graphite_port,timeslot,'as-number',ff.src_as,'bps','outbound',slot_bps)
                graph_counter(graphite_host,graphite_port,timeslot,'as-number',ff.src_as,'fps','outbound',slot_fps)

                -- Dest AS inbound counters
                store_counter(as_stats,timeslot,ff.dst_as,'pps','inbound',slot_pps)
                store_counter(as_stats,timeslot,ff.dst_as,'bps','inbound',slot_bps)
                store_counter(as_stats,timeslot,ff.dst_as,'fps','inbound',slot_fps)
                graph_counter(graphite_host,graphite_port,timeslot,'as-number',ff.dst_as,'pps','inbound',slot_pps)
                graph_counter(graphite_host,graphite_port,timeslot,'as-number',ff.dst_as,'bps','inbound',slot_bps)
                graph_counter(graphite_host,graphite_port,timeslot,'as-number',ff.dst_as,'fps','inbound',slot_fps)
            end

            --print(flow_hash .. ":: " .. ff.src_hostport .. " -> " .. ff.dst_hostport .. " (" .. round(avg_bps,2) .. "bps / " .. round(avg_pps,2) .. "pps ) - " .. observed_duration .. "s")
        end
    end
end

local function clear_old_timeslots(tbl,olderthan)
    local x = 0
    for i, v in ipairs(tbl) do
        if i < olderthan then
            tbl[i] = nil
            x = x+1
        end
    end
    return tbl,x
end

local function create_group_saver(name,cfg)
    local group_cfg = cfg.groups[name]
    local redis_host,redis_port,redis_save_delay = cfg.redis_host,cfg.redis_port,cfg.redis_save_delay
    local last_ran = 0
    local redis = rc.connect(redis_host,redis_port)
    return function()
        if last_ran+redis_save_delay >= os.time() then
            return
        end

        local startclearing = os.time()
        print("Clearing old history...")

        local now = os.time()
        local olderthan = now - cfg.history_max

        local hs_c, ss_c, as_c, hps_c, ps_c = 0,0,0,0,0
        host_stats, hs_c      = clear_old_timeslots(host_stats,olderthan)
        subnet_stats, ss_c    = clear_old_timeslots(subnet_stats,olderthan)
        as_stats, as_c        = clear_old_timeslots(as_stats,olderthan)
        hostport_stats, hps_c = clear_old_timeslots(hostport_stats,olderthan)
        protocol_stats, ps_c  = clear_old_timeslots(protocol_stats,olderthan)
        print("Cleared records HS: " .. hs_c .. " SS: " .. ss_c .. " AS: " .. as_c .. " HPS: " .. hps_c .. " PS: " .. ps_c)
        print("Clearing history took " .. os.time() - startclearing .. " seconds")

        local startsaving = os.time()
        print("Saving stats to redis...") 
        redis:set('host_stats',mp.pack(host_stats))
        redis:set('subnet_stats',mp.pack(subnet_stats))
        redis:set('as_stats',mp.pack(as_stats))
        redis:set('hostport_stats',mp.pack(hostport_stats))
        redis:set('protocol_stats',mp.pack(protocol_stats))

        last_ran = os.time()
        print("Saving history took " .. os.time() - startclearing .. " seconds")
    end
end

local triggered = {}

local function trigger_actions(anomaly,epoch,anomaly_actions,action_defs)
    for action_name,action_config in pairs(anomaly_actions) do
        -- If this trigger has already fired
        local anomaly_action_key = anomaly.name .. ':' .. action_name
        if triggered[anomaly_action_key] ~= anomaly.started and os.time() - epoch >= action_config.delay then
            triggered[anomaly_action_key] = anomaly.started
            print("Anomaly " .. anomaly.name .. " triggered action " .. action_name)
            local action = action_defs[action_name]
            if action.type == 'exec' then
                local command = interp(action.cmd,anomaly)
                print(command)
                os.execute(command)
            else
                print("Unknown action type configured: " .. action.type)
            end
        end
    end
end

local function trigger_inactive(anomaly,anomaly_actions,action_defs)
    return trigger_actions(anomaly,anomaly.stopped,anomaly_actions,action_defs)
end

local function trigger_active(anomaly,anomaly_actions,action_defs)
    return trigger_actions(anomaly,anomaly.started,anomaly_actions,action_defs)
end

local function create_group_eventer(name,cfg)
    local group_cfg = cfg.groups[name]
    local thresholds = group_cfg.thresholds
    local active_timeout, idle_timeout, slot_length = group_cfg.active_timeout,group_cfg.idle_timeout, group_cfg.slot_length
    local last_ran = 0
    local anomalies = {}
    local historical = {}
    return function()
        if last_ran+10 >= os.time() then
            return
        end

        for name, tconfig in pairs(thresholds) do
            -- Calculate time slots over which to look for threshold data
            local now = os.time()
            local time_start, time_end = now - (6*active_timeout), now - active_timeout


            -- If this is an absolute AS check then
            if tconfig.type == 'as-abs' then
                local high_water, low_water, duration, expires = tconfig.high_water, tconfig.low_water, tconfig.duration, tconfig.expires
                local as_number, metric, direction = tconfig.as_number, tconfig.metric, tconfig.direction

                local slots = get_timeslots(as_stats,time_start,time_end,slot_length,as_number,metric,direction)

                if anomalies[name] then -- This threshold is currently in alert mode
                    local anomaly = anomalies[name]

                    -- If value is less than low water
                    local inactive_time,inactive_stopped,trigger_value,trough_value,sum_value,readings = 0,0,0,0,anomaly.sum_value,anomaly.readings
                    for i = 1, #slots, 1 do
                        local ts,value = unpack(slots[i]) 
                        if value < high_water then
                            inactive_stopped = ts
                            trigger_value = value
                            if trough_value > value then
                                trough_value = value
                            end
                            inactive_time = inactive_time + slot_length
                        else
                            inactive_time = 0
                            sum_value = sum_value + value
                            readings = readings + 1
                        end
                    end

                    anomaly.trough_value = round(trough_value,2)
                    anomaly.sum_value = sum_value
                    anomaly.readings = readings
                    anomaly.avg_value = round(sum_value / readings,2)

                    if inactive_time >= duration then -- If this has been inactive for longer than duration, then disable and trigger
                        anomaly.stopped = inactive_stopped
                        anomaly.stopped_readable = os.date("%c", inactive_stopped)
                        anomaly.stop_value = round(trigger_value,2)
                        print("Anomaly inactive:")
                        rPrint(anomaly)
                        trigger_inactive(anomaly,tconfig.on_inactive,cfg.actions)
                        historical[anomalies[name].started .. '_' .. name] = anomaly
                        anomalies[name] = nil
                        anomaly = nil
                    else
                        print("Anomaly on " .. name .. " still active, duration " .. (os.time() - anomaly.started) .. "s")
                        rPrint(anomaly)
                        trigger_active(anomaly,tconfig.on_active,cfg.actions)
                    end

                else 
                    -- If value is greater than
                    local active_time,active_started,trigger_value,peak_value,sum_value,readings = 0,0,0,0,0,0
                    for i = 1, #slots, 1 do
                       local ts,value = unpack(slots[i]) 
                       if value > high_water then
                            sum_value = sum_value + value
                            readings = readings + 1
                            active_started = ts
                            trigger_value = value
                            if peak_value < value then
                                peak_value = round(value,2)
                            end
                            active_time = active_time + slot_length
                        else
                            peak_value = 0
                            active_time = 0
                        end

                    end
                    if active_time >= duration then -- If this has been active for longer than duration, then activate and trigger
                        local anomaly = {
                            high_water       = high_water,
                            low_water        = low_water,
                            trigger_duration = duration,
                            as_number        = as_number,
                            metric           = metric,
                            direction        = direction,
                            readings         = readings,
                            sum_value        = sum_value,
                            started          = active_started,
                            started_readable = os.date("%c", active_started),
                            start_value      = round(trigger_value,2),
                            peak_value       = round(peak_value,2),
                            name             = name,
                        }

                        anomalies[name] = anomaly
                        print("Anomaly active:")
                        rPrint(anomaly)
                        trigger_active(anomaly,tconfig.on_active,cfg.actions)
                    end
                end
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

local bin_masks = {}
for i=1,32 do
    bin_masks[tostring(i)] = bit.lshift(bit.tobit((2^i)-1), 32-i)
end

local bin_inverted_masks = {}
for i=1,32 do
local i = tostring(i)
    bin_inverted_masks[i] = bit.bxor(bin_masks[i], bin_masks["32"])
end

-- Convert subnets to top / bottom addresses
local ranges = {}
for range, prefixes in ipairs(config.ranges) do
    ranges[range] = {}
    for i,prefix in pairs(prefixes) do
        local a, b, a1, a2, a3, a4, mask = prefix:find( '(%d+).(%d+).(%d+).(%d+)/(%d+)')
        if not a then 
            return print('Invalid IP ' .. prefix .. ' in group ' .. range) 
        end
        local o1,o2,o3,o4 = tonumber( a1 ), tonumber( a2 ), tonumber( a3 ), tonumber( a4 )

        local ipno = o1^24 + o2^16 + o3^8 + o4
        local nos = {}
        nos[1] = bit.band(ipno,bin_masks[prefix])
        nos[2] = bit.bor(nos[1],bin_inverted_masks[prefix])
        ranges[range][i] = nos
    end

end

ipfix.configure(config,elements)
ipfix.load_templates()

for grpname,grpcfg in pairs(config.groups or {}) do
    local steps = {}
    config.ip_ranges = ranges
    steps[#steps+1] = create_group_listener(grpname,config)
    steps[#steps+1] = create_group_statter(grpname,config)
    steps[#steps+1] = create_group_eventer(grpname,config)
    steps[#steps+1] = create_group_saver(grpname,config)
    steps[#steps+1] = create_group_sender(grpname,config)
    groups[#groups+1] = steps
end

local x = 1
while true do
    for i=1,#groups do
        local steps = groups[i]
        local ret
        for j=1,#steps do
            local step = steps[j]
            ret = step(ret)
        end
    end
    x = x+1
end 

ProFi:stop()
ProFi:writeReport( 'profile.txt' )
