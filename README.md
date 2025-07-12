# elasticAgentSSH

Purpose is to install a SIEM agent onto an Ubuntu AWS EC2 server, monitor for activity and gain security hardening recommendations.
_Assumptions - Elastic Instance (free trial available) and AWS EC2 host (free tier available)_

1.  Configure Fleet Agent for Elastic
2.  Install Fleet Agent and Enroll Host
3.  Search and Discover Data
4.  Pin and Narrow Down the Applicable Data
5.  Extract the Data Results in JSON
6.  Obtain Summarization and Improvement Suggestions
7.  Formal Incident Report with NIST 800-53 Mapping
<br><br><br>



One.  Configure Fleet Agent for Elastic
<img width="1636" height="958" alt="image" src="https://github.com/user-attachments/assets/c80e6c8f-bd33-4045-baa1-b285bd4685df" />

   <br>
2.  Install Fleet Agent and Enroll Host
<br>  
<img width="1647" height="969" alt="image" src="https://github.com/user-attachments/assets/0da460d3-fd54-4632-b3e8-3cceaaf3cf2f" />

<br>   
3.  Search and Discover Data
<img width="1640" height="971" alt="image" src="https://github.com/user-attachments/assets/cde244aa-ffa7-4ce4-88a4-6f8619b713b6" />
<br>   
4.  Pin and Narrow Down the Applicable Data
<br>
<img width="1633" height="972" alt="image" src="https://github.com/user-attachments/assets/e547d7c2-73af-4982-8882-76fa8e424cc2" />
<br>
<img width="1611" height="932" alt="image" src="https://github.com/user-attachments/assets/f3643a0b-fb13-46e1-a3ff-0bd5eb9f30d7" />
<br>
<img width="1603" height="972" alt="image" src="https://github.com/user-attachments/assets/b0273a69-aff8-43c5-b512-824675e11bd0" />
<br>   
5.  Extract the Data Results in JSON
<br>
Pivot to the Discover Tab
<br>
<img width="1592" height="969" alt="image" src="https://github.com/user-attachments/assets/1bcbc195-60b4-40ed-9d0c-5c4971fbe772" />
<br>
Create the view with SSH logins and failures and 'Inspect' the query and response <br>

<img width="1592" height="969" alt="image" src="https://github.com/user-attachments/assets/85ace01a-f0f8-41b3-85ed-43e3cb8db1c4" />




<br>
Save the response JSON to a file
<img width="1595" height="964" alt="image" src="https://github.com/user-attachments/assets/295ec781-27f1-4bda-85af-ad2b5c51f8bc" />





   
6.  Obtain Summarization and Improvement Suggestions
<br>
Conversate with ChatGPT and give context.<br>
Upload the JSON file
<img width="649" height="603" alt="image" src="https://github.com/user-attachments/assets/4865db3b-6586-4aa4-bfef-c954c82d8451" />

<br>
Request a markdown formatted threat timeline as such:

| Timestamp (UTC)     | Source IP     | City, Region    | Org (ASN)         | User   | Method    | Outcome    |
| ------------------- | ------------- | --------------- | ----------------- | ------ | --------- | ---------- |
| 2025-07-11 22:08:02 | 216.76.55.177 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |
| 2025-07-11 22:17:10 | 216.76.55.177 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |
| 2025-07-11 23:13:26 | 216.76.55.177 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |
| 2025-07-11 23:46:12 | 216.76.55.177 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |
| 2025-07-12 13:45:56 | 216.76.55.145 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |


| Timestamp (UTC)     | Source IP      | Location          | Org (ASN)                 | User      | Outcome   |
| ------------------- | -------------- | ----------------- | ------------------------- | --------- | --------- |
| 2025-07-11 22:08:26 | 166.155.4.51   | Oklahoma City, OK | CELLCO-PART (Verizon)     | `a`       | ❌ Invalid |
| 2025-07-12 00:37:05 | 47.239.244.99  | Hong Kong         | Alibaba US Technology Co. | *(blank)* | ❌ Invalid |
| 2025-07-12 01:29:57 | 47.251.168.129 | Los Angeles, CA   | Alibaba US Technology Co. | *(blank)* | ❌ Invalid |
| 2025-07-12 09:32:30 | 138.2.109.83   | Singapore         | Oracle-BMC (SG)           | *(blank)* | ❌ Invalid |


<br>
Additionally, if you'd like to request a fully formatted Incident Report, it can be generated as such.<br>
<br><br>

7.  Formal Incident Report with NIST 800-53 Mapping
  
---

# 🛡️ Security Incident Report: SSH Access Review

## 📅 Date Range Reviewed

**July 11, 2025 — July 12, 2025 (UTC)**

## 🖥️ Affected System

- **Hostname:** `ip-172-31-38-189`
- **Instance ID:** `i-0cfa212979575969f`
- **Cloud Provider:** AWS EC2
- **OS:** Ubuntu 24.04.2 LTS (Noble Numbat)
- **Architecture:** x86\_64
- **Agent:** Filebeat 9.0.3
- **Logging Source:** `/var/log/auth.log`

---

## 🔍 Summary

This report analyzes SSH login activity captured on the EC2 instance from authentication logs collected via Filebeat and visualized in Kibana. The review covers both legitimate access and potentially malicious login attempts, with a focus on geolocation, frequency, and authentication outcomes.

---

## ✅ Successful SSH Logins

Legitimate access was detected from a consistent IP block in San Antonio, Texas. All logins used the `publickey` method, indicating key-based authentication.

| Timestamp (UTC)     | Source IP     | City, Region    | Org (ASN)         | User   | Method    | Outcome    |
| ------------------- | ------------- | --------------- | ----------------- | ------ | --------- | ---------- |
| 2025-07-11 22:08:02 | 216.76.55.177 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |
| 2025-07-11 22:17:10 | 216.76.55.177 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |
| 2025-07-11 23:13:26 | 216.76.55.177 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |
| 2025-07-11 23:46:12 | 216.76.55.177 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |
| 2025-07-12 13:45:56 | 216.76.55.145 | San Antonio, TX | BELLSOUTH-NET-BLK | ubuntu | publickey | ✅ Accepted |

---

## ❌ Failed SSH Attempts (Suspicious Activity)

Multiple failed SSH login attempts were recorded from globally distributed IPs, likely indicative of brute-force or credential stuffing bots.

| Timestamp (UTC)     | Source IP      | Location          | Org (ASN)                 | Username  | Outcome   |
| ------------------- | -------------- | ----------------- | ------------------------- | --------- | --------- |
| 2025-07-11 22:08:26 | 166.155.4.51   | Oklahoma City, OK | CELLCO-PART (Verizon)     | `a`       | ❌ Invalid |
| 2025-07-12 00:37:05 | 47.239.244.99  | Hong Kong         | Alibaba US Technology Co. | *(blank)* | ❌ Invalid |
| 2025-07-12 01:29:57 | 47.251.168.129 | California, US    | Alibaba US Technology Co. | *(blank)* | ❌ Invalid |
| 2025-07-12 09:32:30 | 138.2.109.83   | Singapore         | Oracle-BMC                | *(blank)* | ❌ Invalid |

---

## ⚠️ Threat Analysis

- **Consistency in Source IP:** All successful logins originated from Texas IPs under the same ASN, suggesting a likely trusted admin or service.
- **Geographic Disparity:** Failed logins came from Asia, California, and Oklahoma — not previously associated with successful sessions.
- **Username Patterns:** Most failed attempts lacked a username or used a single character (e.g., `a`), a common brute-force signature.
- **Timing:** Clustered attempts in early UTC hours indicate automated scanning behavior.

---

## 🛡️ Recommendations

### 🔒 Access Control

- Restrict SSH access via AWS Security Groups to known static IPs.
- Change SSH port from `22` to a high-numbered, non-standard port.
- Disable password authentication in `/etc/ssh/sshd_config`:
  ```bash
  PasswordAuthentication no
  PermitRootLogin no
  AllowUsers ubuntu
  ```

### 🚨 Detection & Response

- Install and configure **Fail2Ban** or equivalent to block brute-force attempts.
- Monitor logs for repeated failed SSH attempts from the same IPs.
- Set Kibana/Elastic alerts:
  - More than 5 failed logins in 5 minutes
  - SSH from unknown geographic regions

### 🔐 SSH Key Hygiene

- Audit `~/.ssh/authorized_keys` for unauthorized or outdated keys.
- Rotate all SSH keys and reissue them only to trusted users.

---

## 📊 Suggested Kibana Visualizations

- Geo map of login attempts
- Bar chart: Success vs. Failure counts per hour
- Table: Top IPs by login failures

---

## 🧩 NIST 800-53 Control Mapping

| **Control ID** | **Control Title**                     | **Description / Relevance**                                                                                          |
| -------------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **AC-2**       | Account Management                    | Monitoring logins (especially failed attempts) supports active account management and detection of misuse.           |
| **AC-3**       | Access Enforcement                    | Restricting SSH to specific users and IPs enforces access control decisions.                                         |
| **AC-6**       | Least Privilege                       | Limiting SSH to a specific user (`ubuntu`) and disabling root login supports least privilege.                        |
| **AU-2**       | Audit Events                          | Collecting SSH logs via Filebeat supports audit requirements.                                                        |
| **AU-6**       | Audit Review, Analysis, and Reporting | Your Kibana log review satisfies the requirement to analyze audit records for indications of inappropriate activity. |
| **AU-8**       | Time Stamps                           | Logs include UTC timestamps — critical for correlation and forensic analysis.                                        |
| **AU-12**      | Audit Generation                      | Use of Filebeat to generate and send logs fulfills the system audit requirement.                                     |
| **CA-7**       | Continuous Monitoring                 | Regular log review and alerting through Kibana/Elastic aligns with continuous monitoring best practices.             |
| **CM-6**       | Configuration Settings                | Disabling password authentication and enforcing SSH key usage is a secure configuration control.                     |
| **IA-2**       | Identification and Authentication     | SSH key-based access with user restrictions is a strong implementation of IA.                                        |
| **IR-4**       | Incident Handling                     | Identifying and documenting unauthorized login attempts supports incident response protocols.                        |
| **PE-20**      | Asset Monitoring                      | Monitoring cloud assets and logging user access aligns with virtual asset security.                                  |
| **SC-7**       | Boundary Protection                   | Limiting SSH access to trusted IPs via AWS Security Groups aligns with boundary defense.                             |
| **SI-4**       | System Monitoring                     | Elastic and Kibana visualizations provide real-time system monitoring and threat intel correlation.                  |

---

## 🧠 Conclusion

While no unauthorized access was successful, your logs indicate that your EC2 instance is **actively targeted** by external IPs. The best defense includes reducing the attack surface, tightening authentication controls, and enabling real-time detection.

---

*Report generated via log analysis and enrichment from Filebeat/Kibana data on 2025-07-12.*

