<p align="center">
  <img src="https://img.shields.io/badge/lab-GOAD--Light-6d28d9?style=flat-square" alt="lab">
  <img src="https://img.shields.io/badge/Active%20Directory-Kerberos%20%C2%B7%20SMB%20%C2%B7%20LDAP-0e7490?style=flat-square" alt="ad">
  <img src="https://img.shields.io/badge/phase-1%20of%202-db2777?style=flat-square" alt="phase">
</p>

<h1 align="center">GOAD-Light — AD Attack Path<br><sub>Part 1: From Recon to Credential Access</sub></h1>

<p align="center">
  A hands-on write-up of my walkthrough through <b>GOAD-Light</b> (Game of Active Directory by Orange Cyberdefense):<br>
  from an empty <code>nmap</code> range to valid domain credentials, with commands, output analysis and defensive recommendations.
</p>

---

## TL;DR

Three hosts, two domains, and both domain controllers answering unauthenticated requests — the whole path below was walked without a single credential until the very end:

- **Recon** — `nxc smb 192.168.56.0/24` mapped three hosts across `sevenkingdoms.local` and `north.sevenkingdoms.local`, and surfaced two weaknesses at once: `CASTELBLACK` has **SMB signing disabled** (NTLM Relay candidate) and both DCs allow **null sessions**.
- **Enumeration** — anonymous `nxc smb --users` returned ten accounts, including `samwell.tarly`, whose description field literally reads `Password : Heartsbane`. No exploit needed to learn a password.
- **Credential access** — **AS-REP Roasting** against `brandon.stark` produced a crackable `$krb5asrep$` hash → valid domain credentials.
- **Kerberoasting** — with those credentials, a TGS for `jon.snow` was requested and cracked offline with rockyou.
- **Honest negative result** — the cracked `jon.snow` password did **not** authenticate (`STATUS_LOGON_FAILURE`), which is documented in the report rather than glossed over.

## Lab at a glance

| Host | IP | Domain | Role | SMB signing | Null auth |
|---|---|---|---|---|---|
| KINGSLANDING | `192.168.56.10` | `sevenkingdoms.local` | Domain Controller | ✅ | ✅ |
| WINTERFELL | `192.168.56.11` | `north.sevenkingdoms.local` | Domain Controller | ✅ | ✅ |
| CASTELBLACK | `192.168.56.22` | `north.sevenkingdoms.local` | Member server | ❌ | ❌ |

## Findings

| # | Finding | Severity |
|---|---|---|
| 1 | SMB signing disabled — NTLM Relay candidate (`CASTELBLACK`) | High |
| 2 | Kerberos pre-authentication disabled (`brandon.stark`) | High |
| 3 | Kerberoastable service account with a dictionary password (`jon.snow`) | High |
| 4 | Weak password policy — rockyou cracks domain credentials | High |
| 5 | Anonymous SMB sessions allow user enumeration (both DCs) | Medium |
| 6 | Password hint exposed in the account description (`samwell.tarly`) | Medium |
| 7 | LLMNR/NBT-NS/WPAD answered — interception path | Medium |

Each finding in [the report](report/goad-light-part1.md#4-findings) is mapped to MITRE ATT&CK, followed by concrete remediation and detection guidance.

## Repository structure

```
goad-light/
├── README.md                     ← you are here
├── report/
│   └── goad-light-part1.md       ← full write-up: recon → credential access
└── assets/                       ← 21 screenshots, numbered in reading order
    ├── 01-root-shell.png
    ├── 02-nxc-smb-sweep.png
    ├── ...
    └── 21-credential-reuse-check.png
```

## Skills demonstrated

`NetExec` · `Nmap` · `enum4linux` · `mitm6` · `Impacket (GetNPUsers / GetUserSPNs)` · `John the Ripper` · Kerberos abuse (`AS-REP Roasting`, `Kerberoasting`) · SMB enumeration · null sessions · output analysis and reporting · remediation mapping to MITRE ATT&CK

## Scope and ethics

Everything in this repository was performed inside an **isolated training lab** (`192.168.56.0/24`, virtual machines, no external network). Credentials and hashes that appear on screenshots are the lab's publicly documented defaults — they authenticate nothing outside the lab.

This is a learning artefact, not an attack kit. Do not run any of this against systems you do not own or lack written permission to test.

## Status

**Part 1 of 2.** Part 2 covers MSSQL, `SeImpersonatePrivilege` → PrintSpoofer → `SYSTEM`, BloodHound path analysis and cross-domain lateral movement.
