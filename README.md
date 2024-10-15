# KQL-Queries-

### Failed Login attempts
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by Account, bin(TimeGenerated, 1h)

--- 

### Failed Logins Across Multiple Accounts
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by Account, bin(TimeGenerated, 1h)
| where FailedLogins > 5

---

### Detect Privilege Escalation
SecurityEvent
| where EventID == 4672 // Special Privileges Assigned to New Logon
| summarize Count = count() by Account, TimeGenerated

--- 

### Unusual Network Traffic
NetworkTraffic
| where TotalBytes > 1000000 // Suspicious threshold
| summarize TotalTraffic = sum(TotalBytes) by SrcIP, DstIP, bin(TimeGenerated, 1h)

---

### Audit Logon Events (Success and Failures)
SecurityEvent
| where EventID == 4624 or EventID == 4625
| summarize LogonCount = count() by Account, EventID, bin(TimeGenerated, 1h)


--- 

### Malicious IP Detection
SecurityAlert
| where AlertType == "Malicious IP"
| summarize Count = count() by SrcIP, bin(TimeGenerated, 1h)

---

### Detect Powershell usage
SecurityEvent
| where EventID == 4104 // PowerShell Script Block Logging
| project TimeGenerated, Account, ScriptBlockText

--- 

### Unusual Bhevaiour
SecurityEvent
| where EventID == 4720 // Account created
| join kind=inner (SecurityEvent | where EventID == 4726) on Account
| summarize Count = count() by Account, TimeGenerated

---

### Detect RDP connection
SecurityEvent
| where EventID == 4624 and LogonType == 10 // RDP login
| summarize RDPConnections = count() by Account, bin(TimeGenerated, 1h)

--- 

### Brute Force Detection
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IPAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 10

