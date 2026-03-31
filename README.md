# sentinel-portscan-detection
# 🌐 Port Scanning Detection using Microsoft Sentinel

## 👤 Author
Kulpreet Singh

---

## 🧠 Overview

This project demonstrates detection of port scanning activity using Microsoft Sentinel. 

Port scanning behavior was simulated using Nmap, and detection logic was implemented using KQL to identify multiple destination ports accessed from a single source IP within a short time window.

---

## 🏗️ Architecture
Kali Linux (Nmap Scan)
	↓
Windows Host (WAHEGURU)
	↓
Azure Arc
	↓
Azure Monitor Agent (AMA)
	↓
Data Collection Rule (DCR)
	↓
Log Analytics Workspace (DemoLogAnalyticWorkspace)
	↓
Microsoft Sentinel


---

## 🔍 Data Source

- Windows Security Event Logs  
- Event ID: **5156 (Windows Filtering Platform - Allowed Connection)**  
- Machine: **WAHEGURU**

---

## 🔧 Detection Logic (KQL)

```kql
Event
| where EventID == 5156
| extend SrcIP = extract(@"Source Address:\s+([^\s]+)", 1, RenderedDescription)
| extend destPort = extract(@"Destination Port:\s+([^\s]+)", 1, RenderedDescription)
| where SrcIP != "::1"
| where isnotempty(destPort)
| summarize scan = dcount(destPort) by SrcIP, bin(TimeGenerated, 5m)
| where scan > 3

🎯 Detection Strategy

The detection identifies:

A single source IP
Accessing multiple destination ports
Within a 5-minute time window

This behavior is indicative of port scanning activity.

🎯 Analytics Rule Configuration
Rule Type: Scheduled Query Rule
Query Frequency: Every 5 minutes
Lookup Period: Last 5 minutes
Threshold: More than 3 unique destination ports
Severity: High
MITRE ATT&CK: Discovery (T1046 - Network Service Scanning)
🚨 Incident Generation

When the defined threshold is exceeded:

Alert is triggered
Incident is created in Microsoft Sentinel
Events are grouped for investigation
🤖 Automation

Automation rule implemented:

Assigns incident owner
Adds tag: portscan
Creates investigation task: "Initiate Analysis"
🧪 Attack Simulation

Port scanning was simulated using Nmap from a Kali Linux machine:
nmap -p 1-1000 <target-ip>
This generated multiple connection attempts across ports, triggering detection logic.


