# Phishing Email Investigation – AsyncRAT Delivery Campaign

> Analyst: Rasaq  
> Date: 2026-02-10  
> Incident Type: Phishing / Malware Delivery  
> Severity: High  
> Status: Contained  
> Environment: Windows Endpoint

---

# Executive Summary

A phishing email impersonating a commercial purchase receipt was delivered to organizational users with the objective of distributing AsyncRAT malware.

The email contained a malicious URL that downloaded a payload (`install.exe`) from attacker-controlled infrastructure hosted at `107.175.247.199`. Sandbox detonation confirmed execution of obfuscated PowerShell commands, process injection behavior, persistence via registry Run keys, and outbound command-and-control (C2) communication.

The investigation included:
- Email header analysis
- Threat intelligence enrichment
- URL reputation analysis
- Malware detonation
- IOC extraction
- MITRE ATT&CK mapping
- Containment recommendations

Analysis confirmed the malware family as **AsyncRAT**.

---

# Incident Overview

| Category | Details |
|---|---|
| Attack Type | Phishing |
| Malware Family | AsyncRAT |
| Delivery Method | Malicious URL |
| Initial Vector | Email |
| Objective | Malware Deployment / Remote Access |
| Impact | Potential endpoint compromise |
| Severity | High |

---
# Investigation Timeline

| Time | Event |
|---|---|
| 09:58 UTC | Phishing email received |
| 10:01 UTC | User clicked malicious URL |
| 10:02 UTC | `install.exe` downloaded |
| 10:03 UTC | PowerShell executed encoded payload |
| 10:04 UTC | Registry persistence established |
| 10:05 UTC | Outbound C2 communication observed |

---
## 📧 Email Metadata

| Field | Value |
|-------|-------|
| Subject | `COMMERCIAL PURCHASE RECEIPT ONLINE` |
| From (Display Name) | `ERIKA JOHANA LOPEZ VALIENTE` |
| From (Envelope) | `erikajohana.lopez@uptc.edu.co` |
| Reply-To | `undisclosed-recipients` |
| Return-Path | `erikajohana.lopez@uptc.edu.co` |
| Date/Time  | `2022-10-09 09:58:26` |
| Message-ID | `CABWu4iua5_uex6=G8pi_OJz1tBLJiNakMK-1=7128orpzxbKxw@mail.gmail.com` |
| Recipient | `undisclosed-recipients` |

<img width="646" height="162" alt="Sender" src="https://github.com/user-attachments/assets/481d003b-f77d-4a09-9920-c3fbbb276dd4" />

---

## 🔍 Header Authentication Analysis

| Mechanism | Value / Status | Verdict |
|-----------|----------------|---------|
| **SPF** (Received-SPF) | ` softfail ` |  ❌  |
| **DKIM** (d= selector) | ` fail ` |  ❌ |
| **DMARC** (policy from DNS) | `p=none ` | ⚠️ |
| **Source IP (first relay)** | `18.208.22.104` | Reputation: clean (Amazon)|
| **ASN / Geo** | `AS14618, United States of America` | |

<img width="622" height="93" alt="Authentication result" src="https://github.com/user-attachments/assets/c44ada1d-fc33-49e7-b5b1-2b61dd00bf44" />

<img width="1895" height="655" alt="Source IP_amazon" src="https://github.com/user-attachments/assets/be50d65a-1d39-4b9a-a4c3-b72995c16a55" />

<img width="667" height="573" alt="IP Location" src="https://github.com/user-attachments/assets/19f592fc-1f49-4f30-8218-ba977e6d7f1b" />

---

## 🔗 URL & Attachment Analysis

### URLs Extracted (from body / links)

| URL | Redirects? | Final Destination | Verdict (VT/URLhaus) |
|-----|------------|-------------------|----------------------|
| `http://107.175.247.199/loader/install.exe` | no | `ripley.studio` | malicious  |

<img width="1891" height="791" alt="url" src="https://github.com/user-attachments/assets/ec1416d8-952b-40b5-9f39-0c966a46b3e3" />


### Sandbox detonation summary  
Executed D41tYapPDr.exe, which launched powershell.exe -enc with a Base64‑encoded command. The process injected code into suspended instances of itself and dropped a copy to %AppData%\Roaming\Vlevqbxvsx\Kjcrsvxp.exe. A registry run key was created at HKCU\...\Run for persistence. Network communication was observed with C2 IP 107.175.247.199 (flagged malicious by 12/91 vendors). The sample was identified as AsyncRAT (trojan.msil/scarsi)

<img width="1828" height="414" alt="Process Tree" src="https://github.com/user-attachments/assets/00e6ef4f-4fa1-4b60-b3e4-a50b66394d6c" />

<img width="1710" height="185" alt="Registry key" src="https://github.com/user-attachments/assets/a5679321-8aed-477f-8753-0e312ad0265d" />

<img width="1906" height="622" alt="Cyberchef" src="https://github.com/user-attachments/assets/c1582b2d-edb2-42c2-9260-ef73665d07f2" />

<img width="1700" height="850" alt="Sandbox behaviora grahp " src="https://github.com/user-attachments/assets/4567c416-5535-4244-824e-8391cba6de43" />


---

## 🧠 Indicators of Compromise (IOCs)

| Type | Indicator | Context / Source |
|------|-----------|------------------|
| **IPv4** | `107.175.247.199` | C2 callback |
| **Domain** | `ripley.studio` | URL in email body |
| **URL** | `http://107.175.247.199/loader/install.exe` | Direct download |
| **File Hash (SHA‑256)** | `5ca468704e7ccb8e1b37c0f7595c54df4e2f4035345b6e442e8bd4e11c58f791` | Attachment |
| **Email address** | `erikajohana.lopez@uptc.edu.co` | Reply-To |
| **Sender IP** | `18.208.22.104` | Email gateway log |

<img width="1892" height="793" alt="Screenshot_25-5-2026_14923_www virustotal com" src="https://github.com/user-attachments/assets/9673094a-18c9-44c5-9026-333cdb722495" />

<img width="1893" height="932" alt="HASH ASYNCRAT" src="https://github.com/user-attachments/assets/7b42d695-5f96-49f0-8c35-2fc34a5ba9fc" />

---
## 🎯 MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name | Observed Behavior |
|--------|--------------|----------------|--------------------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Email sent with malicious attachment/link |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | `powershell.exe -enc` executed encoded command |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | Registry key created at `HKCU\...\Run` |
| Defense Evasion | T1027 | Obfuscated Files or Information | Base64-encoded PowerShell command |
| Defense Evasion | T1055 | Process Injection | Code injected into suspended process |
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP communication to C2 `107.175.247.199` |

## 🛡️ Mitigation Recommendations

- [ ] **Email gateway** – Block sender IP `209.85.221.65` (Google outbound) and hosting IP `107.175.247.199`. Add regex for subject lines containing "COMMERCIAL PURCHASE RECEIPT" or "ONLINE 27 NOV". Quarantine any email with a link to `/loader/install.exe` pattern.

- [ ] **Endpoint** – Block file hash `34793C6520DCF3C6130DC031FA640C71` (SHA‑1 of `D41tYapPDr.exe`) across all AV/EDR. Hunt for dropped executable `Kjcrsvxp.exe` in `%AppData%\Roaming\Vlevqbxvsx\`. Terminate any processes named `D41tYapPDr.exe` or `Kjcrsvxp.exe`. Remove registry run key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Kjcrsvxp`.

- [ ] **Scoping the environment** – Search entire network (all endpoints, servers, and historical logs) for the following IOCs:  
  - File hash `34793C6520DCF3C6130DC031FA640C71`  
  - IP `107.175.247.199` (C2)  
  - Registry path `HKCU\...\Run\Kjcrsvxp`  
  - Process names `D41tYapPDr.exe` or `Kjcrsvxp.exe`  
  - PowerShell command line containing `-enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwAG4AZABzACAAQNAwAA==`  
  - Outbound connections to port 443 on `107.175.247.199`  
  - Any `D41tYapPDr.exe` or `install.exe` file on disk. Document all compromised assets for remediation prioritization.

- [ ] **User awareness** – Publish a phishing alert explaining that even emails from a known sender domain (`uptc.edu.co`) with valid SPF/DKIM can carry malicious links. Highlight the $625,000 invoice lure and instruct users to verify any unexpected purchase receipts by phone before clicking.

- [ ] **Mailbox rules** – Scan all mailboxes for unexpected forwarding rules or auto‑reply rules created around the time of incident. Look for rules that move emails to "RSS Feeds" or delete them – common AsyncRAT post‑compromise actions.

- [ ] **IOC sharing** – Submit the following to MISP or internal threat intel platform:  
  - IP `107.175.247.199` (C2)  
  - Domain `trendmicro.com` (observed in IP hostname, but verify – it may be a decoy)  
  - File hash `34793C6520DCF3C6130DC031FA640C71`  
  - Registry path `HKCU\...\Run\Kjcrsvxp`  
  - PowerShell encoded command snippet `UwB0AGEAcgB0AC0AUwBsAGUAZQBwAG4AZABzACAAQNAwAA==`

- [ ] **Network** – Block outbound traffic to `107.175.247.199` at the firewall. Monitor for any HTTP GET requests to `/loader/install.exe`. Implement IDS/IPS rules for AsyncRAT C2 patterns (e.g., specific user‑agent strings or URI lengths).

- [ ] **EDR hunting** – Query for processes with `-enc` flag in command line, especially those launching from temporary or desktop folders. Hunt for processes that create multiple suspended child processes of the same executable.

---

## 📈 Lessons Learned & Reflection

- **What worked well:**  
  - SPF and DMARC checks quickly confirmed the email originated from a legitimate Google IP (209.85.221.65) spoofing the `uptc.edu.co` domain, highlighting that authentication alone does not guarantee safety.  
  - VirusTotal and Malpedia identified the payload as AsyncRAT (trojan.msil/scarsi) with 53/72 detections, providing immediate threat context.  
  - Joe Sandbox’s 100% confidence detonation clearly showed process injection, encoded PowerShell, registry persistence, and C2 communication, enabling swift IOC extraction.

- **What could be improved:**  
  - Automate extraction and decoding of Base64‑encoded PowerShell commands (e.g., using CyberChef or a Python script) to reveal the full script without manual effort.  
  - Implement an internal blocklist for IP `107.175.247.199` and file hash `34793C6520DCF3C6130DC031FA640C71` across all endpoints and email gateways.  
  - Enhance email gateway rules to detect executable downloads from newly registered or low‑reputation domains/IPs even when SPF/DKIM pass.

- **Key takeaway:**  
  - An email that passes SPF, DKIM, and DMARC can still deliver malware. Always sandbox links and attachments – never trust authentication headers alone.  
  - AsyncRAT establishes persistence via `HKCU\...\Run` and drops copies in `%AppData%\Roaming\`, so these locations should be routinely checked during incident response.  
  - Process trees revealing multiple suspended instances of the same executable or `powershell -enc` are high‑confidence IOCs for code injection and should trigger immediate containment.

---

## 🔗 References / Tools Used

- Email Header Analyzer Notepad++
- URLhaus / VirusTotal / AbuseIPDB
- `CyberChef`

---

*Template last updated: 2026-02-10*
