# detection-lab

A home detection-engineering lab: **Wazuh SIEM + Sysmon** on Windows, with **6 custom detections** mapped to **MITRE ATT&CK**. Each one has a Wazuh rule, a portable Sigma rule, an attack I ran myself to trigger it, a screenshot of the alert, and false-positive notes.

## Architecture

```
Windows 11 endpoint                                     Wazuh manager
├─ Sysmon (SwiftOnSecurity config)  ─┐                  ├─ windows_eventchannel decoder
├─ Security log (4624/4625/4720/...) ├─ Wazuh agent ──► ├─ local_rules.xml (rules 100101-100107)
└─ PowerShell/Operational (4104)    ─┘                  └─ Dashboard: alerts + MITRE mapping
```

## Detections

| # | Detection | Log source | ATT&CK | Wazuh rule | Sigma | Tested |
|---|---|---|---|---|---|---|
| 1 | Brute force (5+ failures in 2 min, same IP) | Security 4625 | T1110.001 | 100101 | `sigma/01` | ☐ |
| 2 | Password spray (one IP, 5+ usernames) | Security 4625 | T1110.003 | 100102 | `sigma/02` | ☐ |
| 3 | New account / added to Administrators | Security 4720, 4732 | T1136.001, T1098 | 100103-4 | `sigma/03` | ☐ |
| 4 | Suspicious PowerShell (encoded, IEX, download) | PowerShell 4104 | T1059.001 | 100105 | `sigma/04` | ☐ |
| 5 | Discovery commands (whoami, net, nltest) | Sysmon 1 | T1033, T1087 | 100106 | `sigma/05` | ☐ |
| 6 | Kerberoasting (RC4 service ticket) | Security 4769 (DC) | T1558.003 | 100107 | `sigma/06` | ☐ (AD lab) |

Tick each one only after the alert fires in my lab, with the screenshot saved in `evidence/`.

## Repo layout

```
wazuh/local_rules.xml   Wazuh custom rules (correlation: frequency, same/different field)
sigma/*.yml             The same detections as vendor-neutral Sigma rules
attack-tests.md         Exactly how I triggered each detection
evidence/               Alert screenshots + notes, one per detection
```

## Evidence

> _For each detection: the attack command, the alert screenshot, and one line on false positives I saw._

| # | Screenshot | What I saw / false positives |
|---|---|---|
| 0 | [Sysmon installed](evidence/00-sysmon-installed.webp) · [Operational log](evidence/00-sysmon-operational-log.png) | Sysmon 15.22 + SwiftOnSecurity config, service Running, 7,448 events logged |
| 0b | [Wazuh pipeline + MITRE](evidence/01-wazuh-pipeline-mitre.webp) | Agent → manager → indexer → dashboard working; ~4,000 alerts mapped to ATT&CK (Account Discovery, PowerShell, Command Shell…). Debugging note: the dashboard showed nothing until I found the Windows clock was ~5.5 h off, so every event looked like it came from the future. Fixed with time sync. |
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |

## What I learned

> _Write this after testing: what surprised you, what you tuned, what didn't fire first time and why._

## How I'd explain it in an interview

**Why Sysmon when Windows already has logs?** Default Windows logging misses a lot. Sysmon adds process creation with full command lines and hashes (Event 1), network connections (3), file creation (11) and more. It's the difference between "something happened" and "here's exactly what ran".

**What's Event ID 1, and why does it matter?** Process creation: what ran, its command line, its parent process, the user and the file hash. Most attacks have to run *something*, so it's the most useful single event in endpoint detection.

**Why Sigma as well as Wazuh rules?** Sigma is vendor-neutral. The same rule converts to Splunk SPL, Microsoft Sentinel KQL or Elastic queries. Writing in Sigma shows I can take detections to any SIEM.

**How does rule 100101 work?** It watches Wazuh's built-in failed-logon rule (60122) and fires when it sees 5 matches from the *same IP* within 120 seconds, using `frequency`, `timeframe` and `same_field`.

**How do you tell brute force from a spray?** Brute force means many attempts against one account. A spray means a few attempts against many accounts. Rule 100102 adds `different_field` on the username, so it only fires when the targets differ.

**What's Kerberoasting, and why is RC4 the signal?** Any domain user can request a service ticket for an account with an SPN. The ticket is encrypted with that account's password hash, so an attacker cracks it offline. Modern environments use AES, so an RC4 (0x17) request stands out.

**Biggest false-positive risk?** Discovery commands (rule 100106). Admins run `whoami` and `ipconfig` all day. On its own it's low severity, and it gets valuable when it chains with other alerts from the same host.

---
_Rules written with AI assistance; I deployed them, ran every attack and documented the results myself._
