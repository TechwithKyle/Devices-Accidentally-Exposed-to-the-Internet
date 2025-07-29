<img width="520" height="280" alt="image" src="https://github.com/user-attachments/assets/73a54b52-b945-4fd8-b141-1759c90f785a" />

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

During routine maintenance, the security team is tasked with investigating any VMs in the
shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly
been exposed to the public internet. The goal is to identify any misconfigured VMs and check for
potential brute-force login attempts/successes from external sources. This exercise will specifically 
focus on "kylesvm" device for attempted brute force attacks.

---

## Timeline Summary and Findings 

Kylesvm has been internet facing for one month (2025-06-29T23:37:40.9873809Z - 2025-07-26T07:57:45.8297573Z): 

**Query used to locate events:**

```kql
DeviceInfo
| where DeviceName == "kylesvm" | where IsInternetFacing == true
| order by Timestamp desc
```

Last Internet facing time: 2025-07-26T07:57:45.8297573Z

<img width="1218" height="561" alt="image" src="https://github.com/user-attachments/assets/2b4f8914-164a-45e5-93ef-76da546f2dec" />

---

Several Bad Actors have been discovered attemtping to log into the target machine.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "kylesvm"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock") | where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

<img width="1208" height="563" alt="image" src="https://github.com/user-attachments/assets/a5f36761-20b7-446c-91f2-541b3fb3be06" />

---

The top 5 most failed login attempts IP addresses have not been able to successfully login to my VM

**Query used to locate events:**

```kql
// Take the top IPs with the most logon failures and see if any succeeded to logon
let RemoteIPsInQuestion = dynamic(["80.94.95.54","200.105.196.189", "110.78.165.187", "124.104.144.26", "181.115.190.30", "52.234.251.139", "181.115.172.119"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

### <Query no results>

---

There were no successful brute force attempts on this account. It is unlikely that a one time password guess would succeed.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "kylesvm"
| where LogonType == "Network"
| where ActionType == ("LogonFailed", "LogonSuccess") //| distinct AccountName
| summarize count ()
```

### <Query no results>

---

Checked all of the successful IP addresses for the user to see if any were unusual or from an unexpected location. All were normal.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "kylesvm"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

<img width="631" height="227" alt="image" src="https://github.com/user-attachments/assets/c69bcbaf-84db-4e5d-ad1a-8a6ef2f6ab5c" />

---
 
## Summary

Though this device was exposed to the internet and clear that brute force attempts have taken place, there were no successful brute force attempts or unauthorized access from the legitimate account “shocker”.

---

## Relevant MITRE ATT&CK TTPs:

- T1078 – Valid Accounts
> Activity analyzed to verify if any logons were made with legitimate accounts like “shocker”.

- T1110 – Brute Force
> Multiple failed logon attempts from various remote IPs suggest brute force login attempts.

- T1021.001 – Remote Services: Remote Desktop Protocol
> RemoteInteractive logon attempts from external IPs suggest attackers tried accessing via RDP.

- T1046 – Network Service Scanning *(inferred)*
> The VM being internet-facing likely made it a target for automated scanning.

- T1589.001 – Gather Victim Identity Information: Credentials
> Failed logon attempts could indicate attackers trying to enumerate or guess credentials.

---

## Response Actions:

- Hardened the NSG attached to account “shocker” to allow only RDP traffic from specific endpoints (No public internet access)
- Implemented Account Lockout Policy
- Implemented MFA
