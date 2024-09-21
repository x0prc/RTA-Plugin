![A](https://github.com/user-attachments/assets/d168e9f7-ce2d-4f80-9015-88304508bdf8)
A plugin for Wireshark that provides Real-Time Alerting mechanism for suspicious activities or anomalies in traffic patterns.

# Motivation
While Wireshark provides detailed packet analysis, it does not have built-in alerting mechanisms for suspicious activities or anomalies in traffic patterns. This means users must manually monitor and analyze captured data without automated notifications. This repository automates the said process.

# How Does it Work?
- **Key Features:**
  - Traffic Spikes Detection
  - Uncommon Ports Detection
  - Malformed Packets Detection
  - High Error Rates Detection
  - Known Malicious Signatures Detection
- **Functionalities:**
  - Notifications via Email
  - Writes to a Log file externally

# Pre-Requisites
[Wireshark](https://wireshark.org) <br>
[Lua](https://lua.org) <br>
`cmake`, `glib`, `libpcap`

# Setup
- Install `luarocks` and `luasocket`
- Add the lua file in Wireshark Plugins directory.
- Change values in the `smtp_config` function with your SMTP server, Port, Email Address and Password, Sender and Recipient Email.
- Launch Wireshark. The plugins configured should work and display Alert messages.

# Usage
- On Linux: `~/.local/lib/wireshark/plugins/`
- On Windows: `C:\Program Files\Wireshark\plugins\2.x\`

# Testing
- Simulate attacks or anomalies like DDoS, port scans, or malformed packets.
- Adjust alert thresholds and detection rules as necessary to minimize false positives.

# Future
- **Machine Learning Integration**: Incorporate ML models to predict anomalies based on traffic history.
- **Dashboard**: Develop a real-time dashboard to visualize the traffic patterns and alerts.
