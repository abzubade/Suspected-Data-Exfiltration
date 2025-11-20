## 🕵️‍♂️📤👤 **Threat Hunting Incident - Data Exfiltration from PIP'd Employee**
<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/7ef7cbd1-5837-4ee9-9ac4-a022391fd8c5" />

---

### 📚 **Scenario**
An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities on his corporate device (ENDPOINT-LAB-ZA) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

---

## 📊 **Incident Summary and Findings**  
### **Timeline Overview**  
#### 1. Look for any kind of archive activity

- I did a search within KQL DeviceFileEvents for any activities with zip files, and found a lot of regular archiving logs and moving to a 'backup" folder.

```kql
DeviceFileEvents
| project-away DeviceId
| where DeviceName == "endpoint-za"
| where FileName endswith "zip"
| order by Timestamp desc
```

<img width="1219" height="684" alt="Screenshot 2025-11-19 at 9 21 46 PM" src="https://github.com/user-attachments/assets/4162f0f4-281b-4c9c-90d8-00fb28003edf" />

---

#### 2. Look for any file activity, based on the Timestamp from any discovered process activity

- I identified a ZIP file creation event and used its timestamp to search DeviceProcessEvents for activity occurring two minutes before and after the archive was generated. During that window, I discovered that a PowerShell script silently installed 7-Zip and then used it to compress employee data into an archive.

  ```kql
   let specificTime = datetime(2025-11-20T00:48:57.6034636Z);
  let VMName = "endpoint-za";
  DeviceProcessEvents
  | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
  | where DeviceName == VMName
  | order by Timestamp desc
  | project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath
  ```
<img width="1829" height="416" alt="Screenshot 2025-11-19 at 9 28 28 PM" src="https://github.com/user-attachments/assets/8e663448-664d-4698-94be-74b5fab9abc5" />

  ---

  #### 3. Look for any network activity, based on the Timestamp from the process or file activity

  - I also searched around the same timeframe for any evidence of data exfiltration on the network, and discovered there was a successful connection to a RemoteURL which indicates data was moved to an external blob storage.

  ```kql
  let specificTime = datetime(2025-11-18T23:38:31.6453479Z);
let VMName = "endpoint-za";
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| where RemotePort == "443"
| where isnotempty(RemoteUrl)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl
```
<img width="1107" height="512" alt="Screenshot 2025-11-19 at 11 00 13 PM" src="https://github.com/user-attachments/assets/caac8612-231c-4566-98f5-c8cc44cd90a7" />

---

## Response
- **Contain the threat:** Isolate the device, block the external blob endpoint, terminate malicious PowerShell activity, and revoke the employee’s access sessions.
- **Secure accounts & system:** Reset credentials, remove unauthorized tools/scripts, and collect forensic evidence for investigation.
- **Prevent recurrence:** Implement DLP policies, enforce application control, restrict PowerShell usage, and strengthen monitoring for archive creation and outbound data transfers.
---

## 🛡️ MITRE ATT&CK Mapping

| Tactic                 | Technique ID  | Technique Name                            | Why It Applies |
|------------------------|---------------|---------------------------------------------|----------------|
| Collection             | T1560.001     | Archive Collected Data: Archive via Utility | User zipped employee data using 7-Zip before transfer. |
| Collection             | T1119         | Automated Collection                        | PowerShell script collected and packaged files automatically. |
| Execution              | T1059.001     | PowerShell                                  | PowerShell was used to silently install 7-Zip and process data. |
| Execution / Persistence| T1105         | Ingress Tool Transfer                       | 7-Zip installer was downloaded and executed silently. |
| Exfiltration           | T1567.002     | Exfiltration Over Web Services: HTTPS       | Outbound connection to external blob storage over port 443. |
| Exfiltration           | T1041         | Exfiltration Over C2 Channel                | Data transmitted outbound using an encrypted channel. |
| Command & Control      | T1071.001     | Application Layer Protocol: Web Protocols   | Data sent to a RemoteURL using HTTPS. |

---

## Response



