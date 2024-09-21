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

-- Traffic tracking variables
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
        authentication = "login",  
        ssl = false                 
    }

    if not r then
        print("Failed to send email: " .. e)
    else
        print("Alert email sent successfully!")
    end
end

-- Function to log threats to a file
function log_threat(threat_message)
    local log_file = io.open("RTA_log.txt", "a")
    if log_file then
        log_file:write(threat_message .. "\n")
        log_file:close()
    else
        print("Failed to open log file.")
    end
end

function update_traffic_patterns(src_ip, dst_ip, port)
    if traffic_patterns[src_ip] == nil then
        traffic_patterns[src_ip] = { total_packets = 0, errors = 0, destinations = {} }
    end
    traffic_patterns[src_ip].total_packets = traffic_patterns[src_ip].total_packets + 1
    if traffic_patterns[src_ip].destinations[dst_ip] == nil then
        traffic_patterns[src_ip].destinations[dst_ip] = { total_packets = 0, ports = {} }
    end
    traffic_patterns[src_ip].destinations[dst_ip].total_packets = traffic_patterns[src_ip].destinations[dst_ip].total_packets + 1
    if traffic_patterns[src_ip].destinations[dst_ip].ports[port] == nil then
        traffic_patterns[src_ip].destinations[dst_ip].ports[port] = { count = 0 }
    end
    traffic_patterns[src_ip].destinations[dst_ip].ports[port].count = traffic_patterns[src_ip].destinations[dst_ip].ports[port].count + 1
end

function detect_traffic_spikes(traffic_patterns)
    for src_ip, data in pairs(traffic_patterns) do
        if data.total_packets > traffic_threshold then
            local message = "ALERT: Traffic spike detected from source IP " .. src_ip
            print(message)
            send_email_alert("Traffic Spike Detected", message)
            log_threat(message)
        end
    end
end

function detect_uncommon_ports(traffic_patterns)
    for src_ip, data in pairs(traffic_patterns) do
        for dst_ip, dst_data in pairs(data.destinations) do
            for port, port_data in pairs(dst_data.ports) do
                if not common_ports[port] then
                    local message = "ALERT: Uncommon port detected! Src IP: " .. src_ip .. " Dst IP: " .. dst_ip .. " Port: " .. port
                    print(message)
                    send_email_alert("Uncommon Port Detected", message)
                    log_threat(message)
                end
            end
        end
    end
end

function detect_malformed_packets(pinfo)
    if pinfo.err ~= nil then
        local message = "ALERT: Malformed packet detected! Frame: " .. pinfo.number .. " Reason: " .. pinfo.err
        print(message)
        send_email_alert("Malformed Packet Detected", message)
        log_threat(message)
    end
end

function detect_high_error_rates(traffic_patterns)
    for src_ip, data in pairs(traffic_patterns) do
        if data.errors and data.errors > error_threshold then
            local message = "ALERT: High error rate detected from source IP " .. src_ip .. " with " .. data.errors .. " errors."
            print(message)
            send_email_alert("High Error Rate Detected", message)
            log_threat(message)
        end
    end
end

-- Function to detect known malicious signatures
function detect_known_malicious_signatures(traffic_patterns)
    for src_ip, data in pairs(traffic_patterns) do
        if known_malicious_ips[src_ip] then
            local message = "ALERT: Known malicious IP detected! Src IP: " .. src_ip
            print(message)
            send_email_alert("Malicious IP Detected", message)
            log_threat(message)
        end
    end
end

-- Dissector function
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

    
    update_traffic_patterns(src_ip, dst_ip, dst_port)

    
    detect_traffic_spikes(traffic_patterns)
    detect_uncommon_ports(traffic_patterns)
    detect_malformed_packets(pinfo)
    detect_high_error_rates(traffic_patterns)
    detect_known_malicious_signatures(traffic_patterns)

    pinfo.cols.protocol = "RTA"
end

-- Register the dissector for IP protocol
local ip_table = DissectorTable.get("ip.proto")
ip_table:add(0, anomaly_detector_proto)  -- 0 will apply the dissector to all IP traffic
