# 🐴 Horse Plinko — Cyber Defense Scripts

> A collection of shell scripts and notes developed for the **Hac@UCF Horse Plinko** cyber defense challenge.  
> These tools were created for learning, documentation, and defense automation during the event.

---

## 📚 Table of Contents
- [Overview](#overview)
- [Files and Purpose](#files-and-purpose)
- [Usage](#usage)
- [Safety & Sensitive Data](#safety--sensitive-data)
- [How to Contribute / Update](#how-to-contribute--update)
- [License](#license)
- [Author / Contact](#author--contact)

---

## 🧩 Overview

This repository contains all the scripts, audit tools, and helper utilities used during the **Horse Plinko** cyber defense challenge at **Hac@UCF**.  
Each script focuses on a different aspect of system defense — from firewall and SSH configuration to threat hunting and suspicious file scanning.

The repository is intended as a learning and documentation resource.  
Most scripts include built-in backups or are read-only by design to minimize risk.

---

## ⚙️ Files and Purpose

### 🗄️ `backup_targets.sh`
Creates timestamped backups of key directories (`/etc`, `/var`, `/opt`, `/home`) into a local `.backups` folder.  
Checks free disk space, preserves file permissions, verifies archives, and optionally copies to a remote generator server.  
> ⚠️ Review for any real hostnames/IPs before uploading publicly.

---

### 🔥 `configure_firewall.sh`
Resets and configures a hardened **UFW** firewall setup:
- Sets default `deny incoming` / `allow outgoing`
- Enables logging
- Allows inbound SSH, HTTP, and MySQL
- Restricts outbound traffic to necessary services (DNS, DHCP, backups)
> Safe baseline for most competition environments.

---

### 🧱 `ssh_hardening.sh`
Hardens SSH configuration:
- Removes all SSH keys except for a defined whitelist (`debian`, `jmoney`, `plinktern`)
- Disables root login and password authentication globally
- Limits login attempts (`MaxAuthTries 3`)
- Allows password login only for specific users
- Backs up old SSH keys under `/root/ssh_backups/`
- Validates SSH config before restarting service  
> ⚠️ Only run after confirming your allowed users.

---

### 🧩 `service_audit.sh`
Audits currently running and enabled services:
- Lists all systemd services
- Highlights unknown or suspicious ones
- Searches running processes for reverse shells or downloader patterns
- Displays listening ports and startup entries
- Outputs color-coded, readable findings.

---

### 🧍‍♂️ `sudo_audit.sh`
Audits system sudo configuration:
- Backs up `/etc/sudoers` and `/etc/sudoers.d/`
- Lists all active sudo rules
- Shows users in `sudo` and `wheel` groups
- Flags normal users with admin privileges
- Includes recommended review commands.

---

### 🔍 `scan_suspicious.sh`
Performs a wide system scan for suspicious activity:
- Checks for common reverse-shell patterns
- Lists listening sockets and ports
- Scans web and temp directories for webshell or downloader patterns
- Lists recently modified and SUID files
- Dumps all cron jobs and systemd timers  
- Saves results to `/tmp/scan_suspicious_<PID>.txt`.

---

### 🌐 `scan_webshells.sh`
Scans web directories for malicious uploads and webshells:
- Searches for dangerous PHP functions (`eval`, `base64_decode`, `system`, etc.)
- Detects downloaders (`curl`, `wget`, `| sh`)
- Reports suspect file names and modification times
- Outputs:
  - `/tmp/webshell_scan_<timestamp>.txt` — full results  
  - `/tmp/webshell_suspect_paths_<timestamp>.txt` — deduplicated list of suspect files  
✅ Safe, read-only script for forensic triage.

---

### 🧠 `threat_helper.sh`
Interactive command-line tool for threat response:
- Lists open ports, logged-in users, and suspicious processes
- Lets you inspect a PID (binary path, hash, open files, owner)
- Offers safe quarantine and termination options
- Quarantines binaries to `/root/quarantine/`
- Logs every action to `/var/log/threat_helper/actions.log`  
> Designed for manual use during incidents.

---

### 🕵️ `threat_hunting.md`
Markdown notes and reference commands used during the challenge.  
Includes common investigation steps, patterns to search for, and checklists for live incident response.

---

### 📜 `incident_notes.txt`
Plaintext notes taken during the challenge — records of what was found, how it was mitigated, and lessons learned.

---

## 🧰 Usage

Make all scripts executable before running:

### 🧭 Notes

This repository is intended for educational and defensive research only.
Do not use these tools on systems or networks without explicit authorization.

---
```bash
chmod +x *.sh

# Example commands
sudo ./backup_targets.sh
sudo ./configure_firewall.sh
sudo ./ssh_hardening.sh
sudo ./sudo_audit.sh
sudo ./scan_suspicious.sh
sudo ./scan_webshells.sh
sudo ./threat_helper.sh

GitHub: github.com/JayF-cs
Event: Hac@UCF — Horse Plinko Cyber Challenge
