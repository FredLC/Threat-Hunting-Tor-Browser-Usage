# 🛡️ Threat Hunt Report: Suspected Tor Browser Activity on Endpoint

## 📋 Summary
  
- **Date:** *March 22, 2025*  
- **Environment:** Windows 10 Endpoint (Lab Simulation)  
- **Objective:** Investigate potential use of the Tor Browser to anonymize outbound traffic and evade monitoring controls.

---

## 📖 Situation

During a routine review of outbound network activity, I was tasked to investigate a potential case of anonymized traffic from a corporate endpoint. The concern was that a user may be using the **Tor Browser** to bypass internal content filtering and security monitoring — behavior that is often associated with unauthorized or high-risk activity.

This investigation simulated a real-world threat scenario where Tor is used for encrypted communications, potential Command and Control (C2) traffic, or dark web access.

---

## ⚙️ Threat Simulation

To assess our detection coverage, I replicated Tor usage in a lab environment:

- Downloaded and executed the **Tor Browser Bundle**
- Observed host-level telemetry with **Microsoft Defender for Endpoint**
- Monitored process behavior and outbound network activity
- Cross-referenced known **Tor exit node IPs** from [https://check.torproject.org/exit-addresses](https://check.torproject.org/exit-addresses)

---

## 🎯 Detection Strategy

My detection and hunting approach focused on the following signals:

- **Process Execution:** `firefox.exe` running from the `Tor Browser` install directory
- **Unusual Network Ports:** Outbound traffic to **port 9050, 9001, 9150, 9030**
- **Known Exit Nodes:** Traffic to IPs from the public Tor exit node list

---

## 🎯 MITRE ATT&CK Mapping

| Tactic              | Technique                        | ID         |
|---------------------|----------------------------------|------------|
| Defense Evasion     | Proxy: Tor                       | T1090.003  |
| Command and Control | Encrypted Channel (Tor)          | T1573.002  |

---

## 🔍 Hunting Queries (Microsoft Defender)

### 1. Unusual Firefox Execution Path (Tor Browser)

```kusto
DeviceProcessEvents
| where FileName in~ ("firefox.exe", "tor.exe")
| where FolderPath has "Tor Browser"
```
![chatgpt_query1](https://github.com/user-attachments/assets/2f522677-a225-490f-a301-82c46d0ca55e)

### 2. Outbound Traffic to Known Tor Ports

```kusto
DeviceNetworkEvents
| where RemotePort in (9001, 9030, 9050, 9051, 9150, 9151, 8443, 7070, 8118, 5000, 9100, 9005)
```

![chatgpt_query3](https://github.com/user-attachments/assets/88f76a40-267c-4e3a-b8d1-874b01e67a36)

### 3. Traffic to Known Tor Exit Nodes

```kusto
DeviceNetworkEvents
| where RemoteIP in~ (
    "185.220.101.1", "51.254.45.15", "204.13.200.2", "185.220.100.254"
	...
)
```
![chatgpt_query2](https://github.com/user-attachments/assets/6ff248b3-7f64-4876-b8e9-fb31f16651e8)

## 🧠 Findings
- Process Behavior: firefox.exe launched from a user-accessible path linked to the Tor Browser (C:\Users\labuser\Desktop\Tor Browser\...)

- Network Activity: Connections observed on ports 9100 and 9005, which are ports associated with Tor network traffic

- Exit Node Traffic: Outbound connections matched known Tor IPs from the official list


## 🛠️ Recommendations
Block: Prevent execution of unauthorized anonymizers like Tor via Defender ASR or AppLocker

Alert: Set custom alerts on traffic to Tor ports or IPs

Monitor: Review process paths and network activity for unusual encryption or proxy behavior

Educate: Train end users on acceptable use policies and the risks of anonymizing tools in a corporate environment

