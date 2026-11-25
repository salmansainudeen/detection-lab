# Triage: rule 92058, Application Compatibility Database launched (level 12)

**Date:** 25 Nov 2026 · **Host:** LAPTOP-D69HQ5QK (agent `vivobook`) · **User:** salma · **MITRE:** T1546.011 Application Shimming

## Alert
- Process: `sdbinst.exe` · Parent: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Command line: **not logged** (gap)

## Investigation
Checked which custom shims are installed:

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom"
```
```
AsusDialService.exe          {22221111-1111-1111-1111-111111111111}.sdb
patchsdbtest.exe             {22221111-1111-1111-1111-111111111111}.sdb
patchsdbtestHardBlock.exe    {22221111-1111-1111-1111-111111111111}.sdb
PioneerGame.exe              {22221111-1111-1111-1111-111111111111}.sdb
```
Install timestamp `134326871880454337` (Windows FILETIME) = **31 Aug 2026 21:59 UTC**, so it was months old.

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" | Get-ItemProperty | Select DatabaseDescription, DatabasePath
```
```
Microsoft Windows Application Compatibility Fix Database   C:\Windows\AppPatch\CustomSDB\{22221111-1111-1111-1111-1111...
```

## Verdict
**Benign true positive.** The rule correctly caught shim activity, but the only installed shim is Microsoft's compatibility fix database, in a protected Windows folder (admin rights needed), installed 3 months ago, covering the laptop's own ASUS software.

## Gap / follow-up
- Process command lines weren't captured for this event. Enable "Include command line in process creation events" (Group Policy) so the next triage doesn't need a registry hunt.
- Caveat: an attacker with admin rights could fake a description, which is why location, date and covered programs were all checked, not just the name.
