# Attack tests: how I trigger each detection

Run these **only on my own lab machines**. After each test: find the alert in Wazuh, screenshot it, save it to `evidence/`, and note any false positives.

## Lab setup (once)

**1. Collect the right logs:** add to the agent's `C:\Program Files (x86)\ossec-agent\ossec.conf`, then `Restart-Service WazuhSvc`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
(The Security channel is collected by default.)

**2. Turn on PowerShell script block logging** (needed for 4104), in an admin PowerShell:
```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
```

**3. Load the rules** on the Wazuh manager: copy `wazuh/local_rules.xml` into `/var/ossec/etc/rules/local_rules.xml`, then `sudo systemctl restart wazuh-manager`.

---

## 1. Brute force (T1110.001), rule 100101
From Kali (or any second machine), against the Windows box with SMB enabled:
```bash
hydra -l testuser -P /usr/share/wordlists/fasttrack.txt smb://<windows-ip> -t 1
```
Or locally, 6 times with a wrong password: `runas /user:testuser cmd`
**Expect:** 4625 events, then alert 100101.

## 2. Password spray (T1110.003), rule 100102
Create 5 local test users, then try one wrong password against each:
```bash
for u in user1 user2 user3 user4 user5; do smbclient -L //<windows-ip> -U "$u%Winter2026!" ; done
```
**Expect:** alert 100102 (one IP, different usernames).

## 3. New admin account (T1136.001 / T1098), rules 100103 + 100104
Admin cmd:
```cmd
net user labattacker P@ssw0rd123! /add
net localgroup Administrators labattacker /add
```
**Expect:** 4720 → alert 100103, then 4732 → alert 100104.
**Clean up:** `net user labattacker /delete`

## 4. Suspicious PowerShell (T1059.001), rule 100105
Harmless: it base64-encodes `Write-Output hello` and runs it:
```powershell
$c = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output hello'))
powershell -EncodedCommand $c
IEX "Write-Output 'iex test'"
```
**Expect:** 4104 script block events → alert 100105.

## 5. Discovery via Sysmon (T1033 / T1087), rule 100106
```cmd
whoami /all
net user
systeminfo
```
**Expect:** Sysmon Event ID 1 for each → alert 100106.

## 6. Kerberoasting (T1558.003), rule 100107 (needs the AD lab)
On a domain-joined machine, with a service account that has an SPN:
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/websrv.lab.local"
```
Or from Kali with Impacket: `GetUserSPNs.py lab.local/user:pass -dc-ip <dc-ip> -request`
**Expect:** 4769 with TicketEncryptionType 0x17 on the DC → alert 100107.

---

## Optional: Atomic Red Team
```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics
Invoke-AtomicTest T1136.001 -TestNumbers 1   # create local account
Invoke-AtomicTest T1059.001 -TestNumbers 1   # PowerShell
Invoke-AtomicTest T1087.001 -TestNumbers 1   # account discovery
Invoke-AtomicTest T1136.001 -Cleanup
```
Atomic Red Team is open-source attack simulation by Red Canary; each test maps to one ATT&CK technique.
