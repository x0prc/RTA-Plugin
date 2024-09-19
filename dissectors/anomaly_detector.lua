local smtp = require("socket.smtp")

local anomaly_detector_proto = Proto("RTA", "Anomaly Detector Protocol")

local fields = anomaly_detector_proto.fields
fields.src_ip = ProtoField.ipv4("anomaly_detector.src_ip", "Source IP")
fields.dst_ip = ProtoField.ipv4("anomaly_detector.dst_ip", "Destination IP")
fields.src_port = ProtoField.uint16("anomaly_detector.src_port", "Source Port")
fields.dst_port = ProtoField.uint16("anomaly_detector.dst_port", "Destination Port")

local smtp_config = {
    server = "smtp.example.com",    -- Replace with your SMTP server
    port = 587,                     -- SMTP port (587 for TLS, 465 for SSL)
    user = "your-email@example.com", -- Your email address
    password = "your-password",      -- Your email password
    from = "<your-email@example.com>", -- Sender email
    to = "<recipient-email@example.com>", -- Recipient email
}

local traffic_threshold = 100  
local error_threshold = 10     
local traffic_patterns = {}    
local known_malicious_ips = {  
    ["192.168.1.100"] = true,
    ["10.10.10.10"] = true
}
local common_ports = {         
    [80] = true,    -- HTTP
    [443] = true,   -- HTTPS
    [22] = true,    -- SSH
    [53] = true     -- DNS
}

function send_email_alert(subject, message)
    local msg = {
        headers = {
            to = smtp_config.to,
            subject = subject
        },
        body = message
    }
    
    local r, e = smtp.send {
        from = smtp_config.from,
        rcpt = smtp_config.to,
        source = smtp.message(msg),
        user = smtp_config.user,
        password = smtp_config.password,
        server = smtp_config.server,
        port = smtp_config.port,
        authentication = "login",  -- Authentication method (login for most SMTP servers)
        ssl = false                 -- Set to true for SSL, false for TLS
    }

    if not r then
        print("Failed to send email: " .. e)
    else
        print("Alert email sent successfully!")
    end
end

function detect_anomalies(pkt)
    local src_ip = tostring(ip_src_field())
    local dst_ip = tostring(ip_dst_field())
    local src_port = tonumber(port_src_field())
    local dst_port = tonumber(port_dst_field())
    local packet_len = tonumber(packet_len_field())
    
    -- Port Access
    if dst_port == 22 or dst_port == 3389 then  -- Unusual access to SSH or RDP
        return "Suspicious Access: Unusual port access detected!"
    end
    
    -- DDoS 
    if not traffic_patterns[src_ip] then
        traffic_patterns[src_ip] = {count = 1}
    else
        traffic_patterns[src_ip].count = traffic_patterns[src_ip].count + 1
    end

    if traffic_patterns[src_ip].count > 1000 then  
        return "DDoS Alert: High traffic volume detected!"
    end
    
end

local traffic_threshold = 100  

-- Function to detect traffic spikes
function detect_traffic_spikes(traffic_patterns)
    for src_ip, data in pairs(traffic_patterns) do
        if data.total_packets > traffic_threshold then
            print("ALERT: Traffic spike detected from source IP " .. src_ip)
        end
    end
end

local common_ports = {
    [80] = true,   -- HTTP
    [443] = true,  -- HTTPS
    [22] = true,   -- SSH
    [53] = true    -- DNS
}

-- Function to detect uncommon ports
function detect_uncommon_ports(traffic_patterns)
    for src_ip, data in pairs(traffic_patterns) do
        for dst_ip, dst_data in pairs(data.destinations) do
            for port, port_data in pairs(dst_data.ports) do
                if not common_ports[port] then
                    print("ALERT: Uncommon port detected! Src IP: " .. src_ip .. " Dst IP: " .. dst_ip .. " Port: " .. port)
                end
            end
        end
    end
end

-- Function to detect malformed packets using pinfo structure
function detect_malformed_packets(pinfo)
    if pinfo.err ~= nil then
        print("ALERT: Malformed packet detected! Frame: " .. pinfo.number .. " Reason: " .. pinfo.err)
    end
end

local error_threshold = 10  -- Define a threshold for triggering an alert for high errors

-- Function to detect high error rates
function detect_high_error_rates(traffic_patterns)
    for src_ip, data in pairs(traffic_patterns) do
        if data.errors and data.errors > error_threshold then
            print("ALERT: High error rate detected from source IP " .. src_ip .. " with " .. data.errors .. " errors.")
        end
    end
end

local known_malicious_ips = {
    ["192.168.1.100"] = true,
    ["10.10.10.10"] = true
}

-- Function to detect known malicious signatures
function detect_known_malicious_signatures(traffic_patterns)
    for src_ip, data in pairs(traffic_patterns) do
        if known_malicious_ips[src_ip] then
            print("ALERT: Known malicious IP detected! Src IP: " .. src_ip)
        end
    end
end

function anomaly_detector_proto.dissector(buffer, pinfo, tree)
    if pinfo.ip == nil then return end

    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    local src_port = pinfo.src_port
    local dst_port = pinfo.dst_port

    local subtree = tree:add(anomaly_detector_proto, buffer(), "Anomaly Detector Protocol")
    subtree:add(fields.src_ip, pinfo.src)
    subtree:add(fields.dst_ip, pinfo.dst)
    subtree:add(fields.src_port, src_port)
    subtree:add(fields.dst_port, dst_port)

    -- Update traffic patterns
    update_traffic_patterns(src_ip, dst_ip, dst_port)

    -- Call anomaly detection functions
    detect_traffic_spikes(traffic_patterns)
    detect_uncommon_ports(traffic_patterns)
    detect_malformed_packets(pinfo)  
    detect_high_error_rates(traffic_patterns)
    detect_known_malicious_signatures(traffic_patterns)

    pinfo.cols.protocol = "RTA"
end

local ip_table = DissectorTable.get("ip.proto")
ip_table:add(0, anomaly_detector_proto)