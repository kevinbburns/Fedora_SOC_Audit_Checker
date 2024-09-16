# Fedora SSAE SOC Audit Script

This script is designed to automate various system security audits and checks, ensuring that critical security services, configurations, and packages are installed and properly configured. It generates an HTML report with the audit results using Bootstrap-styled cards to display each section clearly.


## Features

The script performs the following tasks:

1. **Disk Encryption Check:** Verifies if disk encryption (LUKS) is enabled and displays the encryption status.

2. **Secure Boot Check:** Ensures that Secure Boot is enabled to prevent unauthorized bootloaders or operating systems from running.

3. **Antivirus Status Check (ClamAV):** This check shows whether the ClamAV service is running and shows its status. It also checks the last virus database update.

4. **Firewall Status:** Verifies that the system's firewall (firewalld) is active and lists current rules.

5. **Rootkit Hunter (rkhunter) Scan:** Runs rkhunter to check for rootkits or known vulnerabilities.

6. **SELinux Status:** Checks if SELinux is enabled, which adds a mandatory access control (MAC) security layer.

7. **Password Policy Checks:** Check user account password expiration and complexity policies.

8. **Intrusion Detection (Suricata):** Verifies that the Suricata Network Intrusion Detection System (NIDS) is active and running.

9. **File Integrity Monitoring (AIDE):** Runs AIDE to check the integrity of essential system files, ensuring they haven’t been tampered with.

10. **Auditd Status:** Verifies that auditd, the system auditing daemon, is running.

11. **Fail2Ban Status:** Ensures that Fail2Ban is running, providing brute-force attack prevention.

12. **Open Ports and Services:** Lists open ports and services, showing which ones are accessible externally.

13. **Time Synchronization Status (Chrony):** This check ensures that time synchronization is active, ensuring accurate logs and system time.

14. **Unattended Security Updates:** Ensures that DNF-Automatic is active, which automates system updates and security patches.

15. **Package Installation Check:** Verifies that essential security packages are installed (e.g., clamav, firewalld, rkhunter, etc.). The script outputs a green checkmark (✔) for installed packages and a red cross (✘) for missing ones.

16. **Kernel Hardening Configuration:** Automatically creates a /etc/sysctl.d/99-security.conf file (if it doesn’t exist) to apply critical kernel security settings and ensure they are used.


## Installation and Usage
### Requirements

This script is designed to run on Linux distributions that use the **DNF** package manager (such as Fedora, CentOS, or RHEL).

Ensure the following packages are installed before running the script:
```
-dnf
-bash
-clamav
-firewalld
-rkhunter
-aide
-suricata
-audit
-fail2ban
-chrony
-dnf-automatic
```

You can install missing packages with:
```
sudo dnf install clamav firewalld rkhunter aide Suricata audit fail2ban chronic dnf-automatic
```

# Running the Script
1. **Clone or Download** this repository and make the script executable:
```
chmod +x soc_audit_check.sh
```
2. **Run the script** with superuser privileges to ensure all commands execute successfully:
``` 
sudo ./soc_audit_check.sh
```
3. The script will display audit results in the console and generate an HTML report (```soc_audit_report.html```) in the same directory.

## Generated HTML Report

The script generates a user-friendly HTML report styled with **Bootstrap**.
The report organizes each audit section using cards, and the package installation status is displayed with green checkmarks and red crosses for quick visual reference.

The report includes sections like:
* Disk Encryption Status
* Secure Boot Status
* ClamAV Status
* Rootkit Hunter Scan Results
* Firewall Rules
* And more...

# Kernel Hardening

The script checks for and creates ```/etc/sysctl.d/99-security.conf``` if it doesn’t exist. This file enforces key kernel hardening settings, including:

* **ASLR (Address Space Layout Randomization):** Makes it harder for attackers to predict memory addresses, reducing exploit success.

* **SYN Cookies:** Protects against SYN flood attacks, a common form of Denial-of-Service (DoS) attack.

* **Reverse Path Filtering:** Helps prevent IP spoofing by verifying the source of packets.

These kernel parameters are automatically applied when the script runs.

# Example of HTML Report Sections

1. **Disk Encryption Status:**
   - Checks for the presence of LUKS encryption.
   - Example output: "LUKS encryption is enabled on /dev/mapper."

2. **Secure Boot Status:**
   - Ensures that Secure Boot is active to prevent unauthorized boot environments.
   - Example output: "Secure Boot is enabled."

3. **Package Installation Check:**
   - Verifies that all required packages are installed. If a package is missing, the script will display a red cross.
   - Example output:

![image](https://github.com/user-attachments/assets/c26d35e5-67dc-45c2-95d6-42c3a44df432)
     

# Why This Script?

Security audits are critical to protecting a system against known threats and vulnerabilities. 
This script automates the manual process of checking security configurations, saving time and reducing human error. 
Here's why each section of the script is essential:

* Disk Encryption: Ensures that sensitive data is protected from unauthorized access.
* Secure Boot: Protects the boot process by verifying digital signatures.
* Antivirus (ClamAV): Ensures the system is protected against malware.
* Firewall: Ensures that network traffic is appropriately filtered.
* Rootkit Hunter: Detects malicious software that could otherwise go unnoticed.
* SELinux: Ensures mandatory access controls are in place, enforcing strict security policies.
* Password Policies: Ensures password strength and expiration policies reduce the risk of account compromise.
* Suricata (IDS): Detects and alerts on suspicious network activity.
* AIDE: Detects unauthorized file changes that could indicate a breach.
* Auditd: Logs security-relevant events, providing a trail for investigations.
* Fail2Ban: Prevents brute-force attacks on SSH and other services.
* Time Synchronization: Ensures accurate system time for log correlation and analysis.
* Unattended Security Updates: Ensures the system is patched with the latest security fixes.

# Example Use Case

A **SSAE SOC auditor** can use this script to conduct regular audits of Linux systems, ensuring all security measures are active and properly configured. The HTML report provides a clear, organized view of the system’s security posture, making it easier to spot misconfigurations or missing services.

## License

This script is free to use under the **MIT License**. Feel free to modify and distribute it for your security audit processes.

## Closing Notes:

The above README comprehensively explains the script, how to use it, and why each component matters.
It should be a valuable guide for anyone running the script for SOC audit purposes.


