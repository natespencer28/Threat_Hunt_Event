# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/natespencer28/Threat_Hunt_Event/blob/main/Cyber-Range-TORBrowser%20Hunt)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what it looks like when the employee downloaded a TOR installer and did something that resulted in many TOR-related files being copied to the desktop

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "nate-mde-vm"
| where FileName has "torbrowser" or FolderPath has "torbrowser"
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl
```
<img width="914" height="342" alt="image" src="https://github.com/user-attachments/assets/6899531b-440b-4cad-b093-181ee888533d" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "nate-mde-vm"  
| where ProcessCommandLine contains "tor-browser-windows"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="973" height="103" alt="image" src="https://github.com/user-attachments/assets/c08c8348-9b89-4920-bf12-82e27f94e9e1" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "nate-mde-vm"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="919" height="344" alt="image" src="https://github.com/user-attachments/assets/c1cd71d6-2f0a-41c6-84ef-c818519816a1" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. Looks as if the employee on the "nate-mde-vm" device successfully established a connection to the remote IP address `96.9.98.96' on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `
c:\users\natertater\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "nate-mde-vm"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="967" height="245" alt="image" src="https://github.com/user-attachments/assets/c5f669c9-103e-4d8d-ade4-408ee8a90471" />


---

## Chronological Event Timeline 

##TOR Browser Download Detected
 The user initiated a download of the TOR Browser installation package. This was identified through telemetry showing browser-based downloads of files containing "tor" in their names or originating from known TOR-related domains (e.g., torproject.org).


##TOR Browser Installation Confirmed
 Post-download, file creation events show that the user extracted or installed the TOR Browser onto their device. This was evidenced by the appearance of the "Tor Browser" folder in the user’s directory and associated file execution activity.


##Execution of TOR Browser
 The user launched firefox.exe from within the "Tor Browser" directory, confirming that the application was executed rather than simply downloaded. This process was run under the user’s account, with command-line and file path data consistent with the TOR Browser bundle.


##Outbound Network Connections via TOR
 Once executed, the TOR Browser initiated outbound network connections. These connections were identified as originating from firefox.exe located in the "Tor Browser" folder, with several connections targeting public IP addresses across ports commonly associated with TOR relays (e.g., 443, 9001). These outbound connections are consistent with TOR network bootstrap and anonymized browsing behavior.

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
