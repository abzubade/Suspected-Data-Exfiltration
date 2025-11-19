## 🕵️‍♂️📤👤 **Threat Hunting Incident - Data Exfiltration from PIP'd Employee**
<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/7ef7cbd1-5837-4ee9-9ac4-a022391fd8c5" />

---

### 📚 **Scenario**
An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities on his corporate device (ENDPOINT-LAB-ZA) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

---

## 📊 **Incident Summary and Findings**  
### **Timeline Overview**  
1. We did a search within KQL DeviceFileEvents for any activities with zip files, and found a lot of regular archiving logs and moving to a 'backup" folder.

```kql
DeviceFileEvents
| where DeviceName == "endpoint-za"
| where FileName contains "zip"
| order by Timestamp desc
